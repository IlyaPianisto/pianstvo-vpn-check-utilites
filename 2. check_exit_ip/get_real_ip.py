import csv
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_XRAY = r"\xray\xray.exe"
PROXY_PORT = 10808
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(SCRIPT_DIR, ".env")
RESULT_DIR = os.path.join(SCRIPT_DIR, "check_result")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_dns_cache: Dict[str, str] = {}


def log(msg: str = "") -> None:
    print(msg, flush=True)


def load_dotenv(path: str) -> None:
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
    p = raw.strip()
    if p.startswith("& "):
        p = p[2:].strip()
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'"):
        p = p[1:-1]
    return os.path.expanduser(p.strip())


def ensure_xray_path() -> str:
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
    log("\nВыберите метод проверки:")
    log("  1 - 2ip.io     (полные данные + ссылка whois, нужен бесплатный API-ключ)")
    log("  2 - ipinfo.io  (проверка IP, страны и ASN (менее подробно))")
    log("  3 - ip-api.com (дополнительный способ. тоже самое, что и [2])")

    mapping = {
        "1": "2ip",
        "2ip": "2ip",
        "2ip.io": "2ip",
        "2": "ipinfo",
        "ipinfo": "ipinfo",
        "ipinfo.io": "ipinfo",
        "ipconfig": "ipinfo",
        "3": "ip-api",
        "ip-api": "ip-api",
        "ip-api.com": "ip-api",
    }

    while True:
        choice = input("Ваш выбор (1/2/3): ").strip().lower()
        if choice in mapping:
            return mapping[choice]
        log("Неверный выбор. Введите 1, 2 или 3.")


def resolve_entry(addr: str) -> str:
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
    if method == "2ip":
        template = os.environ.get("TWOIP_URL", "https://api.2ip.io/?token={token}")
        return template.format(token=urllib.parse.quote(twoip_token))
    if method == "ipinfo":
        return "https://ipinfo.io/json"
    if method == "ip-api":
        return "http://ip-api.com/json/?fields=status,message,country,countryCode,city,isp,org,as,hosting,query"
    raise ValueError(f"Неизвестный метод: {method}")


def fetch_via_proxy(url: str, port: int) -> Tuple[Optional[Dict[str, Any]], Optional[float], int, str]:
    proxy_url = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        },
    )

    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=10) as resp:
            http_code = resp.getcode() or 200
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = round(time.perf_counter() - t0, 2)
    except urllib.error.HTTPError as e:
        elapsed = round(time.perf_counter() - t0, 2)
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        preview = body.strip().replace("\n", " ")[:120]
        return None, elapsed, e.code, f"HTTP {e.code}: {preview}"
    except urllib.error.URLError as e:
        elapsed = round(time.perf_counter() - t0, 2)
        return None, elapsed, 0, str(e.reason)
    except Exception as e:
        elapsed = round(time.perf_counter() - t0, 2)
        return None, elapsed, 0, f"{type(e).__name__}: {e}"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        preview = body.strip().replace("\n", " ")[:120]
        return None, elapsed, http_code, f"HTTP {http_code}, не JSON: {preview}"

    if not isinstance(data, dict):
        return None, elapsed, http_code, "ожидался JSON-объект"

    return data, elapsed, http_code, ""


def parse_api_response(method: str, data: Dict[str, Any]) -> Tuple[str, str, str, str]:
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

    if method == "ip-api":
        if data.get("status") == "fail":
            return "", "", "", ""
        exit_ip = str(data.get("query") or "").strip()
        code = str(data.get("countryCode") or "").strip()
        country_name = str(data.get("country") or "").strip()
        if code and country_name and code.upper() != country_name.upper():
            country = f"{code} ({country_name})"
        else:
            country = code or country_name
        city = str(data.get("city") or "").strip()
        org_parts: List[str] = []
        as_info = str(data.get("as") or data.get("org") or data.get("isp") or "").strip()
        if as_info:
            org_parts.append(as_info)
        if data.get("hosting") is True:
            org_parts.append("[hosting]")
        org = " ".join(org_parts)
        return exit_ip, country, city, org

    return "", "", "", ""


def save_results_csv(out_path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
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
    log(f"Конфигов: {total} | Метод: {method} | Прокси порт: {PROXY_PORT}")
    log(f"Результат будет сохранён в: {out_path}\n")

    rows: List[Dict[str, Any]] = []
    auth_errors = 0
    interrupted = False

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
                "tag": "http",
                "port": PROXY_PORT,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {},
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

                if not wait_port(PROXY_PORT, proc):
                    status = "XRAY FAIL"
                    try:
                        with open(log_path, "r", encoding="utf-8", errors="replace") as lf:
                            tail = lf.read().strip().splitlines()[-4:]
                    except OSError:
                        tail = []
                    log("    ✗ xray не стартовал: " + " | ".join(tail))

                else:
                    last_err = ""
                    last_code = 0
                    for attempt in (1, 2):
                        data, sec_val, last_code, last_err = fetch_via_proxy(api_url, PROXY_PORT)
                        if data and last_code < 400:
                            exit_ip, country, city, org = parse_api_response(method, data)
                            if exit_ip:
                                sec = sec_val if sec_val is not None else ""
                                auth_errors = 0
                                break
                            last_err = str(data.get("message") or "нет IP в ответе")

                        if last_code in (401, 403):
                            auth_errors += 1
                            break

                        log(f"    … попытка {attempt} неудачна ({last_err or 'нет ответа'})")

                    if exit_ip:
                        extra_info = "  ".join(part for part in (
                            f"{country}/{city}" if city else country,
                            org,
                        ) if part)
                        log(f"    ✓ выход: {exit_ip}  {extra_info}  ({sec} с)")
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