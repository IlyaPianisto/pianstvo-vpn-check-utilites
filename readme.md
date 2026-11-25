# VPN Check Utilities by pianstvo

Консольные утилиты для работы с VPN-подписками и конфигами Xray.

1. **`sub_fetcher`** — скачать подписку и сохранить её содержимое.
2. **`check_exit_ip`** — проверить внешний IP и провайдера каждого конфига.
3. **`txt_to_json_converter`** — превратить ссылки `vless://` / `hysteria2://` в Xray JSON.

Типичный сценарий: получить подписку → сконвертировать ссылки в JSON → проверить выходные IP.

## Состав

| Папка | Что делает                                                                                                              | README |
|---|-------------------------------------------------------------------------------------------------------------------------|---|
| `1. sub_fetcher` | Скачивает подписку, определяет тип и соответсвенно: сохраняет список JSON-конфигов, декодирует Base64 или список ссылок | [подробно](1.%20sub_fetcher/sub_fetcher_readme.md) |
| `2. check_exit_ip` | Запускает каждый конфиг через Xray и собирает CSV-табличку данные о внещнем IP, его стране и провайдере                 | [подробно](2.%20check_exit_ip/check_exit_ip_readme.md) |
| `3. txt_to_json_converter` | Конвертирует `.txt` со ссылками в массив Xray-конфигов `.json`                                                          | [подробно](3.%20txt_to_json_converter/txt_to_json_converter_readme.md) |

## Установка

Нужен Python 3.10+. `sub_fetcher` и `txt_to_json_converter` работают на любой ОС. `check_exit_ip` из коробки идёт со сборкой Xray под Windows 11, но на Linux/macOS достаточно [скачать Xray-core](https://github.com/XTLS/Xray-core/releases/) под свою систему, распаковать архив и указать путь к скачанному файлу при первом запуске скрипта.

```bash
pip install -r requirements.txt
```

Зависимости: `httpx` + `socksio` (запросы подписки, в том числе через SOCKS5) и `python-dotenv`. Сборка Xray под Windows уже лежит в `2. check_exit_ip/xray/`.

## Быстрый старт

Команды выполняются из папки нужной утилиты — `.env`, `configs/` и `check_result/` создаются относительно текущего каталога.

### 1. Получить подписку

```bash
cd "1. sub_fetcher"
python sub_fetcher.py
```

Введите ссылку. Сначала запрос идёт через SOCKS5 `127.0.0.1:10808`, при ошибке — напрямую. Результат в `configs/`: `*_links.txt` или `*_config.json`.

### 2. Сконвертировать ссылки в JSON

```bash
cd "3. txt_to_json_converter"
python converter.py "../1. sub_fetcher/configs/my_links.txt"
```

Без аргумента путь можно ввести вручную. Результат — `configs/my_links.json`.

### 3. Проверить выходные IP

Перед запуском выключите VPN и системный прокси: утилита занимает порт `10808`.

```bash
cd "2. check_exit_ip"
python get_real_ip.py
```

Укажите JSON-файл и сервис проверки: `1` — 2ip.io, `2` — ipinfo.io, `3` — ip-api.com. Результат — CSV в `check_result/`.

## Лицензия

Автор — **IlyaPianisto**. Код проекта распространяется по лицензии [MIT](LICENSE), Copyright (c) 2026 IlyaPianisto.

## Сторонние компоненты

В `2. check_exit_ip/xray/` лежит стороннее ПО, на которое лицензия MIT **не распространяется**:

- Xray-core — [Mozilla Public License 2.0](2.%20check_exit_ip/xray/LICENSE);
- Wintun — [Prebuilt Binaries License](2.%20check_exit_ip/xray/LICENSE-Wintun).


