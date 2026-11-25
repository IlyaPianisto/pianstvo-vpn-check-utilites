# txt_to_json_converter — конвертер ссылок в Xray JSON

Утилита читает `.txt` со списком ссылок `vless://` и `hysteria2://` (`hy2://`) — по одной на строку — и превращает каждую в полноценный JSON-конфиг Xray. На выходе получается один JSON-массив конфигов, который понимает утилита [`2. check_exit_ip`](../2.%20check_exit_ip/check_exit_ip_readme.md).

---

## Что умеет

- Поддерживает ссылки:
  - `vless://...`
  - `hysteria2://...`
  - `hy2://...` (алиас Hysteria2)
- VLESS:
  - транспорты: `tcp` (`raw`), `xhttp` (`splithttp`), `ws`, `grpc`, `httpupgrade`;
  - безопасность: `reality`, `tls`, `none`;
  - параметры: `encryption`, `flow`, `headerType`, `host`, `path`, `mode`, `serviceName`, `authority`;
  - REALITY: `pbk`, `sid`, `sni`, `fp`, `spx`;
  - TLS: `sni`, `fp`, `alpn`, `allowInsecure`/`insecure`.
- Hysteria2:
  - авторизация из userinfo (`user:pass` или просто `user`);
  - `sni`, `fp`, `alpn` (по умолчанию `h3`), `insecure`/`allowInsecure`;
  - `up`/`upmbps`, `down`/`downmbps` (числа трактуются как Мбит/с);
  - obfs `salamander` с `obfs-password`;
  - сборка в нативном формате Xray: `protocol: hysteria`, `version: 2`, QUIC с congestion `bbr`.
- Каждому конфигу задаётся `remarks`: из фрагмента ссылки (`#Имя`), иначе `VLESS_<номер>` или `HY2_<номер>`.
- Строки с `#` в начале и пустые строки пропускаются.
- Неподдерживаемые ссылки и ошибки парсинга не роняют процесс: выводится сообщение с номером строки, остальные ссылки обрабатываются.
- Существующий файл результата не перезаписывается — добавляется `-2`, `-3` и т.д.

---

## Что получается на выходе

Для каждой ссылки собирается чистый конфиг:

- **inbounds**
  - `socks` на `127.0.0.1:10808` (UDP включён);
  - `http` на `127.0.0.1:10809`;
  - sniffing для `http`, `tls`, `quic`.
- **outbounds**
  - `proxy` — целевой сервер из ссылки;
  - `direct` — `freedom`;
  - `block` — `blackhole`.
- **routing** — `domainStrategy: IPIfNonMatch`, пустой список правил.
- **dns** — пустой объект.
- **remarks** — имя сервера.

Все конфиги складываются в один JSON-массив.

---

## Требования

- Python 3.10+.
- Только стандартная библиотека (`json`, `sys`, `pathlib`, `urllib.parse`) — устанавливать ничего не нужно.

---

## Запуск

Способ 1 — передать путь аргументом:

```powershell
cd "3. txt_to_json_converter"
python converter.py "..\1. sub_fetcher\configs\my_links.txt"
```

Способ 2 — интерактивно:

```powershell
cd "3. txt_to_json_converter"
python converter.py
```

```
=== Конвертер VLESS / Hysteria2 -> Xray JSON ===
Укажите путь к .txt файлу со ссылками:
```

Путь можно вводить в кавычках — они будут удалены.

---

## Результат

Файл сохраняется в `configs/` рядом с текущим рабочим каталогом:

```
configs/<имя_входного_файла>.json
```

Например, `my_links.txt` → `configs/my_links.json`. Если такой файл уже есть:

```
configs/my_links-2.json
configs/my_links-3.json
...
```

В консоли по завершении:

```
Готово! Конфиг успешно сохранён: configs\my_links.json
```

---

## Пример входного файла

```text
vless://uuid@example.com:443?type=grpc&security=reality&sni=example.com&pbk=PUBLIC_KEY&sid=abcd&fp=chrome&serviceName=grpc#Мой сервер
hysteria2://password@example.org:443?sni=example.org&obfs=salamander&obfs-password=secret#HY2 сервер
```

После конвертации получится массив из двух Xray-конфигов с `remarks` «Мой сервер» и «HY2 сервер».

---

## Ошибки и пропуски

| Сообщение | Причина |
|---|---|
| `[Пропуск] Строка N: неподдерживаемый формат ссылки.` | Ссылка не `vless://`, `hysteria2://` или `hy2://` |
| `[Ошибка] Строка N: Отсутствует UUID или адрес сервера в ссылке VLESS.` | Некорректная VLESS-ссылка |
| `[Ошибка] Строка N: Для VLESS Reality не указан параметр pbk (publicKey).` | В ссылке `security=reality`, но нет `pbk` |
| `В файле не найдено ни одной корректной ссылки...` | Все строки пустые/неподдерживаемые |
| `Файл не найден: ...` | Неверный путь к `.txt` |

Файл результата в таких случаях не создаётся (если не найдено ни одной валидной ссылки).

---

## Нюансы

- По умолчанию порт — `443`, если в ссылке он не указан.
- Для VLESS по умолчанию `encryption=none` и `flow` пустой.
- Для Hysteria2 `alpn` по умолчанию — `["h3"]`, `fingerprint` — `chrome`.
- Параметр `type=raw` трактуется как `tcp`, `type=splithttp` — как `xhttp`.
- `path` и другие значения из query декодируются из URL-кодировки; списки (`path`, `host`, `alpn`) разбиваются по запятой.
- Конвертер не проверяет доступность сервера — это задача `check_exit_ip`.
