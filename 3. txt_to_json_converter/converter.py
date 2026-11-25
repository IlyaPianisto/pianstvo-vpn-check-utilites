import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlsplit


def get_param(params: Dict[str, List[str]], key: str, default: str = "") -> str:
    """
    Безопасно извлекает первое значение query-параметра из словаря parse_qs.
    """
    values = params.get(key)
    if values and len(values) > 0:
        return values[0].strip()
    return default


def is_truthy(value: str) -> bool:
    """
    Проверяет, является ли строковый параметр логическим True (например, '1', 'true').
    """
    return value.lower() in {"1", "true", "yes"}


def parse_vless_outbound(link: str) -> Dict[str, Any]:
    """
    Парсит ссылку vless:// и возвращает словарь proxy-outbound в формате Xray.
    Поддерживает транспорты tcp, xhttp (splithttp), ws, grpc, httpupgrade,
    а также безопасность reality, tls и none.
    """
    parsed = urlsplit(link)

    if not parsed.hostname or not parsed.username:
        raise ValueError("Отсутствует UUID или адрес сервера в ссылке VLESS.")

    params = parse_qs(parsed.query)
    port = parsed.port or 443
    uuid = unquote(parsed.username)
    encryption = get_param(params, "encryption", "none") or "none"
    flow = get_param(params, "flow", "")

    net_type = get_param(params, "type", "tcp").lower()
    if net_type == "splithttp":
        net_type = "xhttp"
    elif net_type == "raw":
        net_type = "tcp"

    stream_settings: Dict[str, Any] = {
        "network": net_type,
    }

    if net_type == "tcp":
        header_type = get_param(params, "headerType").lower()
        if header_type == "http":
            host = get_param(params, "host")
            path = get_param(params, "path", "/")
            stream_settings["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [p.strip() for p in path.split(",") if p.strip()] or ["/"],
                        "headers": {
                            "Host": [h.strip() for h in host.split(",") if h.strip()]
                        } if host else {},
                    },
                }
            }
        else:
            stream_settings["tcpSettings"] = {}

    elif net_type == "xhttp":
        stream_settings["xhttpSettings"] = {
            "mode": get_param(params, "mode", "auto") or "auto",
            "host": get_param(params, "host", ""),
            "path": unquote(get_param(params, "path", "/")) or "/",
        }

    elif net_type == "ws":
        ws_settings: Dict[str, Any] = {
            "path": unquote(get_param(params, "path", "/")) or "/",
        }
        host = get_param(params, "host")
        if host:
            ws_settings["headers"] = {"Host": host}
        stream_settings["wsSettings"] = ws_settings

    elif net_type == "grpc":
        grpc_settings: Dict[str, Any] = {
            "serviceName": unquote(get_param(params, "serviceName") or get_param(params, "path")),
        }
        if get_param(params, "mode").lower() == "multi":
            grpc_settings["multiMode"] = True
        authority = get_param(params, "authority")
        if authority:
            grpc_settings["authority"] = authority
        stream_settings["grpcSettings"] = grpc_settings

    elif net_type == "httpupgrade":
        stream_settings["httpupgradeSettings"] = {
            "host": get_param(params, "host", ""),
            "path": unquote(get_param(params, "path", "/")) or "/",
        }

    security = get_param(params, "security", "none").lower() or "none"
    stream_settings["security"] = security

    if security == "reality":
        public_key = get_param(params, "pbk")
        if not public_key:
            raise ValueError("Для VLESS Reality не указан параметр pbk (publicKey).")

        reality_settings: Dict[str, Any] = {
            "serverName": get_param(params, "sni") or get_param(params, "host") or parsed.hostname,
            "publicKey": public_key,
            "shortId": get_param(params, "sid", ""),
            "fingerprint": get_param(params, "fp", "chrome") or "chrome",
        }
        spider_x = unquote(get_param(params, "spx"))
        if spider_x:
            reality_settings["spiderX"] = spider_x

        stream_settings["realitySettings"] = reality_settings

    elif security == "tls":
        tls_settings: Dict[str, Any] = {
            "serverName": get_param(params, "sni") or get_param(params, "host") or parsed.hostname,
        }
        fingerprint = get_param(params, "fp")
        if fingerprint:
            tls_settings["fingerprint"] = fingerprint

        alpn = get_param(params, "alpn")
        if alpn:
            tls_settings["alpn"] = [item.strip() for item in unquote(alpn).split(",") if item.strip()]

        if is_truthy(get_param(params, "allowInsecure")) or is_truthy(get_param(params, "insecure")):
            tls_settings["allowInsecure"] = True

        stream_settings["tlsSettings"] = tls_settings

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "encryption": encryption,
                            "flow": flow,
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream_settings,
    }


def parse_hysteria2_outbound(link: str) -> Dict[str, Any]:
    """
    Парсит ссылку hysteria2:// или hy2:// и возвращает proxy-outbound
    в нативном формате Xray (protocol: hysteria, version: 2, finalmask).
    """
    parsed = urlsplit(link)

    if not parsed.hostname:
        raise ValueError("Отсутствует адрес сервера в ссылке Hysteria2.")

    if parsed.username is not None and parsed.password is not None:
        auth = f"{unquote(parsed.username)}:{unquote(parsed.password)}"
    elif parsed.username is not None:
        auth = unquote(parsed.username)
    else:
        auth = ""

    params = parse_qs(parsed.query)
    port = parsed.port or 443
    sni = get_param(params, "sni") or parsed.hostname
    fingerprint = get_param(params, "fp", "chrome") or "chrome"

    alpn_raw = get_param(params, "alpn")
    alpn = (
        [item.strip() for item in unquote(alpn_raw).split(",") if item.strip()]
        if alpn_raw
        else ["h3"]
    )

    hysteria_settings: Dict[str, Any] = {
        "version": 2,
        "auth": auth,
    }

    up = get_param(params, "up") or get_param(params, "upmbps")
    down = get_param(params, "down") or get_param(params, "downmbps")
    if up:
        hysteria_settings["up"] = f"{up} mbps" if up.isdigit() else up
    if down:
        hysteria_settings["down"] = f"{down} mbps" if down.isdigit() else down

    tls_settings: Dict[str, Any] = {
        "serverName": sni,
        "enableSessionResumption": False,
        "fingerprint": fingerprint,
        "alpn": alpn,
    }

    if is_truthy(get_param(params, "insecure")) or is_truthy(get_param(params, "allowInsecure")):
        tls_settings["allowInsecure"] = True

    finalmask: Dict[str, Any] = {
        "quicParams": {
            "debug": False,
            "congestion": "bbr",
        }
    }

    obfs_type = get_param(params, "obfs").lower()
    obfs_password = unquote(get_param(params, "obfs-password"))
    if obfs_type == "salamander" and obfs_password:
        finalmask["udp"] = [
            {
                "type": "salamander",
                "settings": {
                    "password": obfs_password,
                },
            }
        ]

    return {
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {
            "address": parsed.hostname,
            "port": port,
            "version": 2,
        },
        "streamSettings": {
            "network": "hysteria",
            "hysteriaSettings": hysteria_settings,
            "security": "tls",
            "tlsSettings": tls_settings,
            "finalmask": finalmask,
        },
    }


def build_xray_config(proxy_outbound: Dict[str, Any], remarks: str) -> Dict[str, Any]:
    """
    Собирает полноценный, но чистый (пустой от лишних правил и списков)
    JSON-конфиг Xray для одного сервера.
    """
    return {
        "dns": {},
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [],
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "udp": True,
                    "auth": "noauth",
                },
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": [
                        "http",
                        "tls",
                        "quic",
                    ],
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {
                    "allowTransparent": False,
                },
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": [
                        "http",
                        "tls",
                        "quic",
                    ],
                },
            },
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
            },
            {
                "tag": "block",
                "protocol": "blackhole",
            },
        ],
        "remarks": remarks,
    }


def parse_link_to_config(link: str, index: int) -> Optional[Dict[str, Any]]:
    """
    Определяет протокол ссылки и возвращает готовый объект Xray-конфига.
    """
    clean_link = link.strip()
    if not clean_link or clean_link.startswith("#"):
        return None

    parsed = urlsplit(clean_link)
    lower_link = clean_link.lower()

    if lower_link.startswith("vless://"):
        proxy_outbound = parse_vless_outbound(clean_link)
        default_remark = f"VLESS_{index}"
    elif lower_link.startswith("hysteria2://") or lower_link.startswith("hy2://"):
        proxy_outbound = parse_hysteria2_outbound(clean_link)
        default_remark = f"HY2_{index}"
    else:
        print(f"[Пропуск] Строка {index}: неподдерживаемый формат ссылки.")
        return None

    remarks = unquote(parsed.fragment).strip() if parsed.fragment else default_remark
    if not remarks:
        remarks = default_remark

    return build_xray_config(proxy_outbound, remarks)


def get_unique_output_path(output_dir: Path, stem: str, suffix: str = ".json") -> Path:
    """
    Возвращает свободный путь для сохранения файла.
    Если файл {stem}{suffix} уже существует, добавляет к имени -2, -3, -4 и т.д.
    """
    candidate = output_dir / f"{stem}{suffix}"
    if not candidate.exists():
        return candidate

    counter = 2
    while True:
        candidate = output_dir / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def convert_file(input_file_path: Path, output_dir: Path = Path("configs")) -> Path:
    """
    Читает ссылки из указанного .txt файла, конвертирует каждую в отдельный
    Xray-конфиг внутри общего JSON-массива и сохраняет в configs/{имя_файла}.json
    (с добавлением -2, -3 и т.д., если файл уже существует).

    Читает ссылки из указанного .txt файла, конвертирует каждую в отдельный
    Xray-конфиг внутри общего JSON-массива и сохраняет в configs/{имя_файла}.json.
    """
    if not input_file_path.exists() or not input_file_path.is_file():
        raise FileNotFoundError(f"Файл не найден: {input_file_path}")

    lines = input_file_path.read_text(encoding="utf-8").splitlines()
    configs_list: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        try:
            config = parse_link_to_config(line, idx)
            if config:
                configs_list.append(config)
        except Exception as err:
            print(f"[Ошибка] Строка {idx}: {err}")

    if not configs_list:
        raise ValueError("В файле не найдено ни одной корректной ссылки vless:// или hysteria2://.")

    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = get_unique_output_path(output_dir, input_file_path.stem, ".json")
    output_path.write_text(
        json.dumps(configs_list, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return output_path


def main() -> None:
    """
    Точка входа: запрашивает путь к .txt файлу (или берёт его из аргументов запуска)
    и запускает конвертацию.
    """
    print("=== Конвертер VLESS / Hysteria2 -> Xray JSON ===")

    if len(sys.argv) > 1:
        raw_path = sys.argv[1]
    else:
        raw_path = input("Укажите путь к .txt файлу со ссылками: ")

    cleaned_path = raw_path.strip().strip('"').strip("'")
    if not cleaned_path:
        print("Путь к файлу не указан. Завершение работы.")
        return

    try:
        saved_file = convert_file(Path(cleaned_path))
        print(f"\nГотово! Конфиг успешно сохранён: {saved_file}")
    except Exception as exc:
        print(f"\nНе удалось выполнить конвертацию: {exc}")


if __name__ == "__main__":
    main()