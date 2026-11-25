import asyncio
import base64
import binascii
import json
import os
import random
import re
import uuid
from pathlib import Path

import httpx
from dotenv import load_dotenv

ENV_PATH = Path(".env")

WIN_BUILDS = (
    "10.0.19044",
    "10.0.19045",
    "10.0.22000",
    "10.0.22621",
    "10.0.22631",
    "10.0.26100",
    "10.0.26200",
)


def init_config():
    """Создаёт .env со случайными параметрами устройства при первом запуске и загружает его."""
    if not ENV_PATH.exists():
        hwid = str(uuid.uuid4())
        ua_id = random.randint(10**12, 10**13 - 1)
        ver_os = random.choice(WIN_BUILDS)

        default_env = f"""HWID={hwid}

# Эмуляция клиента
USER_AGENT=Happ/4.3.0/Windows/{ua_id}
DEVICE_OS=Windows
VER_OS={ver_os}
DEVICE_MODEL=Desktop
"""
        ENV_PATH.write_text(default_env, encoding="utf-8")
        print(f"Создан файл {ENV_PATH} с автоматически сгенерированными настройками")

    load_dotenv(ENV_PATH)


init_config()

PROXY = "socks5://127.0.0.1:10808"
HWID = os.getenv("HWID")
USER_AGENT = os.getenv("USER_AGENT")
DEVICE_OS = os.getenv("DEVICE_OS")
VER_OS = os.getenv("VER_OS")
DEVICE_MODEL = os.getenv("DEVICE_MODEL")

OUTPUT_DIR = "configs"
JSON_OUTPUT = "vpn_config.json"
TEXT_OUTPUT = "vpn_links.txt"


def try_decode_base64(text: str):
    """Возвращает расшифрованный текст или None, если это не Base64."""
    compact = "".join(text.split())
    normalized = compact.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def extract_profile_title(raw_title: str | None) -> str | None:
    """Декодирует profile-title (включая base64:...) и чистит под безопасное имя файла."""
    if not raw_title:
        return None

    title = raw_title.strip()
    if title.lower().startswith("base64:"):
        decoded = try_decode_base64(title[7:])
        if not decoded:
            return None
        title = decoded.strip()

    clean = re.sub(r"[^\w\-]+", "_", title, flags=re.UNICODE)
    clean = re.sub(r"_+", "_", clean).strip("_-")[:50]

    return clean or None


def parse_content(raw_text: str) -> dict:
    """Определяет формат ответа: JSON (xray / sing-box / generic) или список ссылок."""
    decoded = try_decode_base64(raw_text)
    was_base64 = decoded is not None
    if was_base64:
        print("Контент расшифрован из Base64.")
        text = decoded
    else:
        print("Это не Base64, проверяем на JSON/текст...")
        text = raw_text

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, (dict, list)):
        print("Успешно распарсен JSON конфигурации!")

        if isinstance(data, dict) and isinstance(data.get("outbounds"), list):
            is_xray = any(isinstance(o, dict) and "protocol" in o for o in data["outbounds"])
            kind = "json_xray" if is_xray else "json_singbox"
            print("Получено конфигов: 1 шт.")
            return {"type": kind, "data": data}

        if isinstance(data, list) and any(isinstance(item, dict) and "outbounds" in item for item in data):
            print(f"Получено конфигов: {len(data)} шт.")
            return {"type": "json_xray", "data": data}

        return {"type": "json_generic", "data": data}

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    print(f"Найдено строк/ключей: {len(lines)}")
    return {"type": "raw_lines", "lines": lines, "was_base64": was_base64}


async def fetch_and_parse_subscription(url: str):
    """Запрашивает подписку (сначала через прокси, при ошибке — напрямую) и парсит ответ."""
    headers = {
        "User-Agent": USER_AGENT,
        "x-hwid": HWID,
        "x-device-os": DEVICE_OS,
        "x-ver-os": VER_OS,
        "x-device-model": DEVICE_MODEL,
        "Accept": "application/json, text/plain, */*",
    }

    attempts = []
    if PROXY:
        attempts.append((f"через прокси ({PROXY})", PROXY))
    attempts.append(("напрямую (без прокси)", None))

    print("\nСтучимся по ссылке подписки с эмуляцией клиента...")

    timeout = httpx.Timeout(15.0, connect=5.0)

    for mode_label, proxy_url in attempts:
        print(f"Попытка подключения {mode_label}...")
        try:
            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=timeout,
                follow_redirects=True,
                trust_env=False,
            ) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                raw_text = response.text.strip()

                print(f"Успешно ({mode_label})! Статус: {response.status_code}. Получено символов: {len(raw_text)}.")
                for name in ("profile-title", "subscription-userinfo", "content-type"):
                    if name in response.headers:
                        print(f"    {name}: {response.headers[name]}")

                result = parse_content(raw_text)
                result["profile_title"] = extract_profile_title(response.headers.get("profile-title"))
                return result

        except Exception as e:
            if proxy_url is not None:
                print(f"Не удалось через прокси ({type(e).__name__}: {e}). Переключаемся на прямое подключение...")
            else:
                print(f"ERROR: ошибка при прямом запросе подписки: {e}")

    return None


def unique_path(path: str) -> str:
    """Если файл уже есть, добавляет -2, -3 и т.д. перед расширением."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    n = 2
    while os.path.exists(f"{base}-{n}{ext}"):
        n += 1
    return f"{base}-{n}{ext}"


def save_result(result: dict) -> str:
    """JSON сохраняем в .json, всё остальное в .txt. Существующие файлы не перезаписываем."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    title = result.get("profile_title")

    if result["type"].startswith("json"):
        base_name = f"{title}_config.json" if title else JSON_OUTPUT
        filename = unique_path(os.path.join(OUTPUT_DIR, base_name))
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result["data"], f, indent=2, ensure_ascii=False)
        return filename

    base_name = f"{title}_links.txt" if title else TEXT_OUTPUT
    filename = unique_path(os.path.join(OUTPUT_DIR, base_name))
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(result["lines"]) + "\n")
    return filename


async def main():
    print("=== Парсер конфигураций XRAY-JSON ===")
    test_url = input("Введи ссылку на подписку: ").strip()
    if not test_url:
        print("Ссылка не введена!")
        return

    result = await fetch_and_parse_subscription(test_url)
    if not result:
        return

    print("\n" + "=" * 30 + " РЕЗУЛЬТАТ ПАРСИНГА " + "=" * 30)
    filename = save_result(result)

    if result["type"].startswith("json"):
        print(f"JSON-конфиг ({result['type']}) сохранён в файл: {filename}")
    else:
        source = "Base64" if result["was_base64"] else "обычный текст"
        print(f"Список ссылок ({len(result['lines'])} шт., источник: {source}) сохранён в файл: {filename}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())