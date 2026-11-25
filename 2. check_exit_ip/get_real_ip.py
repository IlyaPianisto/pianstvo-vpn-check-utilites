"""
Объединённый скрипт проверки выходных IP-адресов VPN-конфигов через Xray (SOCKS5).

Поддерживаемые методы проверки:
  1 — 2ip.io    (https://api.2ip.io/?token=..., требует бесплатный API-токен в .env)
  2 — ipinfo.io (https://ipinfo.io/json)
  3 — myip.com  (https://api.myip.com)

Результаты сохраняются в папку check_result/ в формате CSV:
  check_result/{имя_конфига}-exit-{метод}.csv

Внешние библиотеки (pip) не требуются — используется только стандартная библиотека Python.
"""

import csv
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_XRAY = r"\xray\xray.exe"
SOCKS_PORT = 10808
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(SCRIPT_DIR, ".env")
RESULT_DIR = os.path.join(SCRIPT_DIR, "check_result")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_dns_cache: Dict[str, str] = {}


def log(msg: str = "") -> None:
    """Печатает строку с мгновенным сбросом буфера."""
    print(msg, flush=True)

def load_dotenv(path: str) -> None:
    """
    Загружает переменные из .env в os.environ.
    Уже заданные в системе переменные окружения не перезаписываются.
    """
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as e:
        log(f"ERROR: Не удалось прочитать {path}: {e}")


def save_env_var(path: str, key: str, value: str) -> None:
    """
    Применяет переменную в текущем процессе (os.environ) и сохраняет/обновляет её в .env.
    """
    os.environ[key] = value

    lines: List[str] = []
    updated = False
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []

    new_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, _ = stripped.partition("=")
            if k.strip() == key:
                new_lines.append(f"{key}={value}")
                updated = True
                continue
        new_lines.append(line)

    if not updated:
        new_lines.append(f"{key}={value}")

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")
    except OSError as e:
        log(f"ERROR: Не удалось записать {key} в {path}: {e}")


def ensure_twoip_token() -> str:
    """
    Проверяет наличие TWOIP_TOKEN в окружении / .env.
    Если ключа нет — выводит инструкцию по получению, запрашивает его у пользователя,
    применяет в os.environ и сохраняет в .env.
    """
    token = os.environ.get("TWOIP_TOKEN", "").strip()
    if token:
        return token

    log()
    log("=" * 60)
    log("Не найден API-ключ 2ip.io (переменная TWOIP_TOKEN).")
    log("Как получить бесплатный ключ (10 000 запросов в месяц):")
    log("  1. Откройте сайт: https://2ip.io/ru/free/  (или https://2ip.io/free/)")
    log("  2. Нажмите «Попробовать бесплатно» и войдите / зарегистрируйтесь.")
    log("  3. Скопируйте ваш API-токен из личного кабинета.")
    log("=" * 60)

    while True:
        entered = input("Вставьте API-ключ 2ip.io (или нажмите Enter для выхода): ").strip()
        entered = entered.strip('"').strip("'")
        if not entered:
            sys.exit("Токен 2ip.io не указан. Работа скрипта завершена.")
        save_env_var(ENV_PATH, "TWOIP_TOKEN", entered)
        log(f"Токен применён в окружении и сохранён в: {ENV_PATH}\n")
        return entered


def clean_path_input(raw: str) -> str:
    """
    Очищает путь, введённый или перетащенный мышкой в консоль Windows (CMD / PowerShell).
    """
    p = raw.strip()
    # В PowerShell при перетаскивании файла иногда подставляется префикс "& 'путь'"
    if p.startswith("& "):
        p = p[2:].strip()
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'"):
        p = p[1:-1]
    return os.path.expanduser(p.strip())


def ensure_xray_path() -> str:
    """
    Ищет xray.exe по переменной XRAY_PATH, дефолтному пути или рядом со скриптом.
    Если не найден — запрашивает путь у пользователя и сохраняет в .env.
    """
    candidates = [
        os.environ.get("XRAY_PATH", "").strip(),
        DEFAULT_XRAY,
        os.path.join(SCRIPT_DIR, "xray", "xray.exe"),
        os.path.join(SCRIPT_DIR, "xray.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path

    log(f"ERROR: xray.exe не найден по стандартному пути: {DEFAULT_XRAY}")
    while True:
        raw = input("Укажите путь к xray.exe (или Enter для выхода): ")
        p = clean_path_input(raw)
        if not p:
            sys.exit("Путь к xray.exe не указан.")
        if os.path.isfile(p):
            save_env_var(ENV_PATH, "XRAY_PATH", p)
            log(f"Путь к xray.exe сохранён в {ENV_PATH}\n")
            return p
        log(f"Файл не найден: {p}")

def prompt_json_path() -> str:
    """Запрашивает у пользователя путь к JSON-файлу с конфигами."""
    while True:
        raw = input("Введите путь к JSON-файлу конфига: ")
        path = clean_path_input(raw)
        if not path:
            log("Путь не может быть пустым. Попробуйте ещё раз.")
            continue
        if not os.path.isfile(path):
            log(f"Файл не найден: {path}")
            continue
        return path


def prompt_method() -> str:
    """
    Запрашивает метод проверки и возвращает внутренний код метода:
    '2ip', 'ipinfo' или 'myip'.
    """
    log("\nВыберите метод проверки:")
    log("  1 - 2ip.io    (полные данные + ссылка whois, нужен бесплатный API-ключ)")
    log("  2 - ipinfo.io (проверка IP, страны и ASN (менее подробно))")
    log("  3 - myip.com (дополнительный способ. функционал как у [2])")

    mapping = {
        "1": "2ip",
        "2ip": "2ip",
        "2ip.io": "2ip",
        "2": "ipinfo",
        "ipinfo": "ipinfo",
        "ipinfo.io": "ipinfo",
        "ipconfig": "ipinfo",  # на случай привычного ввода
        "3": "myip",
        "myip": "myip",
        "myip.com": "myip",
    }

    while True:
        choice = input("Ваш выбор (1/2/3): ").strip().lower()
        if choice in mapping:
            return mapping[choice]
        log("Неверный выбор. Введите 1, 2 или 3.")

def resolve_entry(addr: str) -> str:
    """IP возвращает как есть, домен резолвит в строку 'домен (ip1, ip2)'."""
    try:
        ipaddress.ip_address(addr)
        return addr
    except ValueError:
        pass

    if addr not in _dns_cache:
        try:
            infos = socket.getaddrinfo(addr, None, type=socket.SOCK_STREAM)
            ips = sorted({i[4][0] for i in infos})
            _dns_cache[addr] = f"{addr} ({', '.join(ips)})"
        except socket.gaierror:
            _dns_cache[addr] = f"{addr} (DNS ERR)"
    return _dns_cache[addr]


def get_entry(cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[Any], Optional[str], Optional[str]]:
    """Извлекает из первого прокси-outbound: (адрес, порт, протокол, транспорт)."""
    for o in cfg.get("outbounds", []):
        if o.get("protocol") in ("freedom", "blackhole", "dns"):
            continue
        s = o.get("settings") or {}
        ss = o.get("streamSettings") or {}

        if s.get("vnext"):
            addr = s["vnext"][0].get("address")
            port = s["vnext"][0].get("port")
        elif s.get("servers"):
            addr = s["servers"][0].get("address")
            port = s["servers"][0].get("port")
        else:
            addr = s.get("address")
            port = s.get("port")

        net = ss.get("network") or "-"
        sec = ss.get("security") or "none"
        return addr, port, o.get("protocol"), f"{net}/{sec}"
    return None, None, None, None


def wait_port(port: int, proc: subprocess.Popen, timeout: float = 6.0) -> bool:
    """Ожидает, пока Xray откроет локальный SOCKS5-порт."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False

def build_api_url(method: str, twoip_token: str = "") -> str:
    """Формирует URL запроса для выбранного метода."""
    if method == "2ip":
        template = os.environ.get("TWOIP_URL", "https://api.2ip.io/?token={token}")
        return template.format(token=urllib.parse.quote(twoip_token))
    if method == "ipinfo":
        return "https://ipinfo.io/json"
    if method == "myip":
        return "https://api.myip.com/"
    raise ValueError(f"Неизвестный метод: {method}")


def fetch_via_socks(
                        url: str,
                        port: int,
                        force_ipv4: bool = False,
                                                    ) -> Tuple[Optional[Dict[str, Any]], Optional[float], int, str]:
    """
    Выполняет HTTPS-запрос через локальный SOCKS5-прокси с помощью curl.exe.
    При force_ipv4=False используется socks5h:// (DNS на стороне VPN-сервера).
    При force_ipv4=True домен резолвится в IPv4 (-4) и передаётся через socks5://,
    что обходит сломанный IPv6 на VPS (актуально для Cloudflare / api.myip.com).

    Возвращает кортеж: (json_dict | None, время_в_сек | None, http_code, текст_ошибки).
    """
    proxy_scheme = "socks5" if force_ipv4 else "socks5h"
    cmd = [
        "curl.exe",
        "-sS",
        "-L",
        "--http1.1",
        "--ssl-no-revoke",
        "--connect-timeout", "7",
        "--max-time", "10",
        "--proxy", f"{proxy_scheme}://127.0.0.1:{port}",
        "-A", (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "-H", "Accept: application/json",
        "-w", "\n%{http_code}\n%{time_total}",
    ]
    if force_ipv4:
        cmd.append("-4")
    cmd.append(url)

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return None, None, 0, "curl.exe не найден в системе"
    except Exception as e:
        return None, None, 0, f"{type(e).__name__}: {e}"

    stdout = res.stdout or ""
    parts = stdout.rsplit("\n", 2)
    if len(parts) != 3:
        err = (res.stderr or "").strip() or "пустой ответ"
        return None, None, 0, err

    body, code_str, time_str = parts
    try:
        http_code = int(code_str.strip())
    except ValueError:
        http_code = 0

    try:
        elapsed = round(float(time_str.strip().replace(",", ".")), 2)
    except ValueError:
        elapsed = None

    if http_code == 0:
        err = (res.stderr or "").strip() or "нет соединения"
        return None, elapsed, 0, err

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        preview = body.strip().replace("\n", " ")[:120]
        return None, elapsed, http_code, f"HTTP {http_code}, не JSON: {preview}"

    if http_code >= 400:
        preview = body.strip().replace("\n", " ")[:120]
        return data if isinstance(data, dict) else None, elapsed, http_code, f"HTTP {http_code}: {preview}"

    if not isinstance(data, dict):
        return None, elapsed, http_code, "ожидался JSON-объект"

    return data, elapsed, http_code, ""


def parse_api_response(method: str, data: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """
    Нормализует ответ любого из 3 сервисов в единый набор полей:
      (exit_ip, country, city, org)
    """
    if method == "2ip":
        exit_ip = str(data.get("ip") or "").strip()

        code = str(data.get("code") or "").strip()
        country_name = str(data.get("country") or "").strip()
        if code and country_name and code.upper() != country_name.upper():
            country = f"{code} ({country_name})"
        else:
            country = code or country_name

        city = str(data.get("city") or data.get("region") or "").strip()

        org_parts: List[str] = []
        asn = data.get("asn")
        if isinstance(asn, dict):
            asn_id = asn.get("id")
            asn_name = str(asn.get("name") or "").strip()
            hosting = asn.get("hosting")
            if asn_id not in (None, ""):
                asn_str = str(asn_id).strip()
                org_parts.append(asn_str if asn_str.upper().startswith("AS") else f"AS{asn_str}")
            if asn_name:
                org_parts.append(asn_name)
            if hosting is True:
                org_parts.append("[hosting]")
        elif asn not in (None, ""):
            org_parts.append(str(asn).strip())
        org = " ".join(org_parts)

        return exit_ip, country, city, org

    if method == "ipinfo":
        exit_ip = str(data.get("ip") or "").strip()
        country = str(data.get("country") or "").strip()
        city = str(data.get("city") or "").strip()
        org = str(data.get("org") or "").strip()
        return exit_ip, country, city, org

    if method == "myip":
        exit_ip = str(data.get("ip") or "").strip()
        cc = str(data.get("cc") or "").strip()
        country_name = str(data.get("country") or "").strip()
        if cc and country_name and cc.upper() != country_name.upper():
            country = f"{cc} ({country_name})"
        else:
            country = cc or country_name
        return exit_ip, country, "", ""

    return "", "", "", ""

def save_results_csv(out_path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    """Сохраняет собранную таблицу в CSV (UTF-8 с BOM для корректного открытия в Excel)."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    log("!!! Перед началом обязательно убедитесь, что выключили VPN и Прокси !!!")
    load_dotenv(ENV_PATH)
    xray_exe = ensure_xray_path()
    src_path = prompt_json_path()
    method = prompt_method()
    twoip_token = ""

    if method == "2ip":
        twoip_token = ensure_twoip_token()

    api_url = build_api_url(method, twoip_token)

    try:
        with open(src_path, "r", encoding="utf-8-sig") as f:
            raw_configs = json.load(f)
    except Exception as e:
        sys.exit(f"Ошибка чтения JSON ({src_path}): {e}")

    if isinstance(raw_configs, dict):
        configs = [raw_configs]
    elif isinstance(raw_configs, list):
        configs = raw_configs
    else:
        sys.exit("Неверный формат JSON: ожидался список конфигов или объект.")

    total = len(configs)
    if total == 0:
        sys.exit("В файле нет ни одного конфига.")

    config_stem = os.path.splitext(os.path.basename(src_path))[0]
    out_filename = f"{config_stem}-exit-{method}.csv"
    out_path = os.path.join(RESULT_DIR, out_filename)

    if method == "2ip":
        fieldnames = [
            "idx", "name", "entry", "port", "proto", "transport",
            "exit_ip", "whois_url", "country", "city", "org", "sec", "status",
        ]
    else:
        fieldnames = [
            "idx", "name", "entry", "port", "proto", "transport",
            "exit_ip", "country", "city", "org", "sec", "status",
        ]

    log()
    log(f"Конфигов: {total} | Метод: {method} | SOCKS5 порт: {SOCKS_PORT}")
    log(f"Результат будет сохранён в: {out_path}\n")

    rows: List[Dict[str, Any]] = []
    auth_errors = 0
    interrupted = False
    prefer_ipv4 = False

    try:
        for i, orig_cfg in enumerate(configs):
            if not isinstance(orig_cfg, dict):
                continue

            cfg = dict(orig_cfg)
            name = cfg.get("remarks") or f"#{i}"
            addr, port, proto, transport = get_entry(cfg)
            entry = resolve_entry(addr) if addr else "?"

            log(f"[{i + 1}/{total}] {name}")
            log(f"    вход: {entry}:{port}  {proto} {transport}")

            cfg["inbounds"] = [{
                "tag": "socks",
                "port": SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
            }]

            cfg_path = os.path.join(tempfile.gettempdir(), f"xray_chk_{os.getpid()}_{i}.json")
            log_path = os.path.join(tempfile.gettempdir(), f"xray_chk_{os.getpid()}_{i}.log")

            with open(cfg_path, "w", encoding="utf-8") as cf:
                json.dump(cfg, cf, ensure_ascii=False)

            proc = None
            exit_ip = country = city = org = ""
            sec: Any = ""
            status = "OK"

            try:
                with open(log_path, "w", encoding="utf-8") as logf:
                    proc = subprocess.Popen(
                        [xray_exe, "run", "-c", cfg_path],
                        stdout=logf,
                        stderr=subprocess.STDOUT,
                    )

                if not wait_port(SOCKS_PORT, proc):
                    status = "XRAY FAIL"
                    try:
                        with open(log_path, "r", encoding="utf-8", errors="replace") as lf:
                            tail = lf.read().strip().splitlines()[-4:]
                    except OSError:
                        tail = []
                    log("    ✗ xray не стартовал: " + " | ".join(tail))

                else:
                    data = None
                    last_err = ""
                    last_code = 0
                    used_ipv4 = prefer_ipv4

                    # Попытка 1 — текущий предпочтительный режим;
                    # Попытка 2 — альтернативный (переключение между socks5h и IPv4 socks5)
                    attempts_plan = [prefer_ipv4, not prefer_ipv4]
                    for attempt, use_ipv4 in enumerate(attempts_plan, 1):
                        data, sec_val, last_code, last_err = fetch_via_socks(
                            api_url, SOCKS_PORT, force_ipv4=use_ipv4
                        )
                        if data and data.get("ip") and last_code < 400:
                            sec = sec_val if sec_val is not None else ""
                            auth_errors = 0
                            used_ipv4 = use_ipv4
                            if attempt == 2 and use_ipv4:
                                prefer_ipv4 = True
                            break

                        if last_code in (401, 403):
                            auth_errors += 1
                            break

                        mode_tag = "IPv4" if use_ipv4 else "socks5h"
                        log(f"    … попытка {attempt} [{mode_tag}] неудачна ({last_err or 'нет IP в ответе'})")

                    if data and data.get("ip") and last_code < 400:
                        exit_ip, country, city, org = parse_api_response(method, data)
                        extra_info = "  ".join(part for part in (
                            f"{country}/{city}" if city else country,
                            org,
                        ) if part)
                        ipv4_note = " [IPv4]" if used_ipv4 else ""
                        log(f"    ✓ выход: {exit_ip}  {extra_info}  ({sec} с){ipv4_note}")
                    else:
                        status = f"HTTP {last_code}" if last_code >= 400 else "NO RESPONSE"
                        log(f"    ✗ ошибка запроса: {last_err or 'нет ответа через прокси'}")

            finally:
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                for tmp_f in (cfg_path, log_path):
                    try:
                        os.remove(tmp_f)
                    except OSError:
                        pass

            row: Dict[str, Any] = {
                "idx": i,
                "name": name,
                "entry": entry,
                "port": port,
                "proto": proto,
                "transport": transport,
                "exit_ip": exit_ip,
                "country": country,
                "city": city,
                "org": org,
                "sec": sec,
                "status": status,
            }
            if method == "2ip":
                row["whois_url"] = f"https://2ip.io/whois/?ip={exit_ip}" if exit_ip else ""

            rows.append(row)
            log()

            if method == "2ip" and auth_errors >= 2:
                log("[!] Похоже, API-ключ 2ip.io недействителен или исчерпан лимит.")
                log(f"    Проверьте TWOIP_TOKEN в файле: {ENV_PATH}")
                break

    except KeyboardInterrupt:
        interrupted = True
        log("\n[!] Прервано пользователем (Ctrl+C). Сохраняю уже проверенные результаты...")

    save_results_csv(out_path, fieldnames, rows)

    ok_rows = [r for r in rows if r["status"] == "OK"]
    log("=" * 60)
    prefix = "Прервано, но сохранено" if interrupted else "Готово"
    log(f"{prefix}: {len(ok_rows)}/{len(rows)} ответили (из {total} всего)")
    log(f"Таблица сохранена: {out_path}")
    log(f"Уникальных выходных IP: {len({r['exit_ip'] for r in ok_rows if r['exit_ip']})}")

    if any(r["org"] for r in ok_rows):
        log("\nРаспределение по провайдерам (org):")
        for org_name, cnt in Counter((r["org"] or "?") for r in ok_rows).most_common():
            log(f"  {cnt:3d} × {org_name}")
    elif ok_rows:
        log("\nРаспределение по странам:")
        for country_name, cnt in Counter((r["country"] or "?") for r in ok_rows).most_common():
            log(f"  {cnt:3d} × {country_name}")


if __name__ == "__main__":
    main()