# RawVeil

RawVeil — экспериментальный демон для Linux, который перехватывает исходящий
трафик через `AF_PACKET`, разбирает TLS/QUIC/STUN/RTP, применяет стратегии
фрагментации и переотправляет изменённые кадры через `AF_PACKET` +
`sendmmsg`. Проект не использует NFQUEUE и не является форком zapret,
GoodbyeDPI или аналогичных проектов.

Основная задача — исследовать и воспроизводить поведение DPI на уровне
L2–L4: разрезать TLS ClientHello, менять порядок сегментов, добавлять
fake-пакеты, управлять TCP window и маршрутизировать выбранные адреса через
AmneziaWG/WARP. AWG — опциональный fallback для случаев, когда стратегии не
помогают; для чистой проверки DPI используйте `rawveil.dpi.conf` (`--conf dpi`).

> **Статус:** инженерный прототип, не production-ready. Поведение зависит от
> конкретного DPI, сети и удалённого endpoint. Успешный TLS handshake не
> гарантирует нормальную передачу данных.

## Последние изменения

- Добавлен **read-only захват ответов сервера** (`capture_incoming`):
  отдельный AF_PACKET-сокет на uplink, счётчики `server_frames`,
  `server_tls`, `server_handshakes`, `server_quic` и debug-логи направлений.
  Ответы не изменяются и не переотправляются.
- Добавлен пресет **`rawveil.dpi.conf`** и алиас `--conf dpi`: стратегии без
  AWG/WARP, удобно для чистой проверки DPI.
- AWG переведена в режим **fallback/opt-in**: `RAWVEIL_AWG_MODE=auto|on|off`;
  при `[warp] enabled=false` helper не поднимает туннель.
- Добавлен безопасный `tools/strategy_probe.py` и `make probe` для проверки
  TLS-сегментации на реальных endpoint без изменения сети.
- Обновлены профили и CDN-диапазоны SoundCloud/YouTube; добавлен отдельный
  `youtube_tls` с `split_sni = middle`.

## Содержание

- [Последние изменения](#последние-изменения)
- [Что реализовано](#что-реализовано)
- [Архитектура](#архитектура)
- [Что обходит и что не обходит](#что-обходит-и-что-не-обходит)
- [Известные проблемы](#известные-проблемы)
- [Требования](#требования)
- [Сборка](#сборка)
- [Установка](#установка)
- [CLI](#cli)
- [Конфигурация](#конфигурация)
- [Профили стратегий](#профили-стратегий)
- [AWG/WARP](#awgwarp)
- [Тестирование](#тестирование)
- [Безопасность](#безопасность)
- [Диагностика](#диагностика)
- [Структура](#структура)
- [Планы](#планы)

## Что реализовано

- Демон на C11 с командами `on`, `off`, `status`, `reload`, `--help`,
  `--version`.
- INI-подобный конфиг. Приоритет значений:
  `CLI > файл конфигурации > defaults`.
- Демонизация, pid-файл с `flock`, защита от второго экземпляра,
  readiness-канал: `rawveil on` возвращает ошибку, если демон не стартовал.
- Graceful shutdown по `SIGTERM`/`SIGINT`, перечитывание конфига по
  `SIGHUP`, запись статистики по `SIGUSR1`.
- Drop privileges после открытия raw-сокетов; сохраняются только
  `CAP_NET_RAW`/`CAP_NET_ADMIN` (список настраивается).
- Захват `AF_PACKET` с classic BPF: IPv4/IPv6 TCP/443, media-порты
  `2053,2083,2087,2096,8443`, UDP/443 и UDP `50000-50099`, один VLAN-тег.
- Read-only захват ответов сервера на uplink (`capture_incoming`) с
  TLS/QUIC-счётчиками и debug-логами; не влияет на кадры и маршруты.
- Пресет `rawveil.dpi.conf`: те же стратегии без AWG/WARP; AWG остаётся
  отдельным fallback-транспортом.
- Безопасный разбор Ethernet/VLAN/IPv4/IPv6/TCP/UDP с проверкой длин.
- Разбор TLS ClientHello и SNI, QUIC long/short header, STUN magic cookie,
  RTP.
- Connection tracking с таймаутами, лимитом записей, data-счётчиками и
  freeze для UDP.
- Пересборка IPv4/IPv6 TCP/UDP, TCP options, checksum, нарезка по MTU.
- IP-фрагментация UDP для IPv4 и IPv6 (QUIC/HTTP3).
- Защита от повторного захвата собственных кадров: IPv4 ID / IPv6 flow
  label `0x5256`.
- Режимы `capture_mode=direct|redirect`; в redirect RawVeil переотправляет
  необработанные кадры, чтобы nftables `fwd to dummy` не создавал чёрную
  дыру.
- Стратегии `multisplit`, `fake`, `fakedsplit`, `fake_session`,
  `fake_quic_initial`, `quic_fragment`, `quic_block`, `none` и
  fallback-профиль.
- `tools/strategy_probe.py`: безопасная проверка baseline/TCP-chunks/SNI-
  сегментации/TLS-record split на реальных endpoint без root и без изменения
  сети.
- Per-SNI профили (`filter_sni`, `filter_sni_exclude`, `priority`) с
  фиксацией выбранного профиля за потоком.
- Fake TCP с произвольной длиной SNI: пересобираются TLS record/handshake/
  extension/SNI length-поля; при невозможности fake пропускается, реальный
  SNI не утекает.
- Встроенный DNS-прокси: локальный UDP/TCP listener, DoT (OpenSSL) и DoH
  (libcurl), кеш, strict-режим без plaintext fallback.
- Host helper перехватывает исходящий plain DNS (UDP/TCP 53) через
  `nftables redirect` на DNS-прокси; resolver-конфиг не меняется.
- WARP-списки IP/CIDR и доменов, hot reload, bypass стратегий для WARP.
- Парсинг AmneziaWG-конфига и маршрутизация WARP-назначений в `route` или
  `nft` режиме.
- Host helper: dummy-интерфейс, временная nftables-таблица, автоматическая
  очистка при остановке/падении, systemd unit без автозапуска.
- Unit-тесты и smoke-тесты в private network namespace.

## Архитектура

Схема с host helper:

```text
application
    |
    | outgoing packet
    v
uplink interface
    |
    | nftables netdev/egress: fwd to rvhost0
    v
rvhost0 (dummy)
    |
    | AF_PACKET capture
    v
RawVeil: packet parse -> TLS/SNI -> tracker -> profile -> strategy
    |
    | AF_PACKET TX + sendmmsg
    v
uplink interface
```

Ключевые свойства:

- RawVeil видит **исходящие** пакеты. Ответы сервера и входящий трафик не
  захватываются.
- `replace_original=true` означает, что стратегия сама отправляет
  изменённую/исходную полезную нагрузку. Если оригинальный пакет не был
  подавлен до отправки, возможны дубликаты; это зависит от схемы развёртывания.
- nftables-таблица и dummy создаются только на время работы helper-а и
  удаляются при его завершении.
- Собственные кадры RawVeil не должны повторно попадать в capture; для этого
  используется маркер `0x5256`.

## Что обходит и что не обходит

### Обходит или пытается обходить

| Механизм | Поддержка | Комментарий |
|---|---|---|
| DPI по SNI в TLS ClientHello | частично | split, reverse order, extra split; зависит от TCP reassembly |
| Простой DPI по первому пакету | частично | multisplit/fakedsplit |
| DPI, чувствительный к TTL | экспериментально | fake-пакеты с `fake_ttl` |
| DPI, проверяющий TCP checksum/ACK | экспериментально | `fake_bad_checksum`, `tcp_ack_offset`, `fake_seq_offset` |
| DPI, проверяющий TCP options | экспериментально | `fake_md5sig` |
| DPI, ограничивающий размер TCP window | экспериментально | `wssize` |
| DPI на media-портах | частично | порты из BPF и профиля |
| UDP/STUN/RTP/QUIC Initial | fake, IP-фрагментация, block | QUIC crypto/handshake не реализован |
| QUIC/HTTP3, если DPI не reassembling-ит IP | частично | `quic_fragment`, IPv4/IPv6 |
| QUIC, если DPI блокирует UDP/443 | да | `quic_block`/nft reject → TCP fallback |
| Блокировки по IP/CDN/географии | нет | нужен туннель или другой маршрут |
| ECH/ESNI и зашифрованный SNI | нет | SNI отсутствует в открытом виде |
| Ответы сервера и server-to-client DPI | нет | capture только outgoing |
| HTTP/3 и полноценный QUIC | нет | есть только `fake_quic_initial` |
| IPv6 extension headers | нет | базовый IPv6 поддерживается |
| Фрагментированный TCP/реассемблирование | нет | рассчитано на обычные сегменты |
| Автоматический подбор стратегии под домен | нет | фильтры только по proto/port/L7 |

### Практические ограничения

- Один и тот же профиль применяется ко всем потокам, подходящим по
  `filter_proto`/`filter_ports`/`filter_l7`. Отдельного фильтра по SNI или
  домену нет.
- `split_all=true` и `fake_bad_checksum=true` могут приводить к нулевой
  передаче данных на некоторых потоках. Эти параметры не включены в
  базовый профиль.
- `fake_md5sig`, `wssize`, `fake_seq_offset` и `fake_ttl` меняют поведение
  fake-пакетов и требуют проверки на конкретной сети. Они не гарантируют
  улучшение и могут ломать handshake.
- `desync_data_packets` ограничивает число data-пакетов, к которым
  применяется split/disorder. После достижения cutoff трафик идёт без
  изменения; при DPI, который начинает throttling позже, этого может быть
  недостаточно.
- SNI splitting не помогает, если DPI reassembling-ит TCP или анализирует
  TLS record целиком.
- Смена стратегии не помогает при блокировке по IP, ASN, геолокации или при
  фильтрации на стороне CDN.

## Известные проблемы

1. **Нет универсальной стратегии.** Результат зависит от ISP, DPI, CDN и
   версии TLS. Конфигурация, работающая для одного сервиса, может ухудшать
   другой.
2. **Discord и часть CDN нестабильны.** TLS handshake и HTTP/2 могут
   проходить, но API, WebSocket, gateway или загрузка assets — таймаутиться.
   По внешнему ответу нельзя однозначно отличить SNI-DPI от блокировки по
   IP/flow.
3. **SoundCloud и большие ответы.** HTML может загружаться частично, а
   передача assets останавливаться после первых килобайт. Это похоже на
   throttling в data-фазе; параметр `desync_data_packets` требует подбора.
4. **Только outgoing capture.** Нет аналога `PKT_IN`: RawVeil не видит
   ответы сервера, не может выравнивать window по входящим пакетам и не
   анализирует server-side DPI.
5. **Fake-пакеты эвристические.** Нет полноценной эмуляции TLS/QUIC
   handshake. `fake_sni` пересобирает ClientHello с новой длиной, но fake
   всё равно должен быть отброшен сервером по seq/checksum/TTL.
6. **nftables `PACKET_OUTGOING`.** Классический AF_PACKET tap срабатывает
   после netfilter `OUTPUT`/`POSTROUTING`. Если оригинал дропается до
   `dev_queue_xmit`, RawVeil его не увидит.
7. **Host helper не является универсальным firewall.** Он создаёт
   `netdev`-таблицу с `fwd to` dummy и удаляет её при остановке. Схема
   рассчитана на тестирование и не заменяет продуманный egress-hook.
8. **`threads` зарезервирован.** Используется один capture reader; worker
   pool и `PACKET_FANOUT` ещё не реализованы.
9. **DNS-прокси не перехватывает браузерный DoH/DoT.** Plain DNS
   перехватывается через nft redirect, но приложение со своим DoH на 443
   может обойти proxy; нужен отдельный block/SNI или настройка браузера.
10. **Per-domain профили есть, но SNI недоступен для ECH/QUIC.** Для
    зашифрованного SNI остаются IP/CDN-списки и маршрут через AWG.
11. **Нет автоматического обновления WARP-списков.** После изменения
    списков нужен `SIGHUP`/`reload`.
12. **Тесты не воспроизводят реальный DPI.** Unit/smoke-тесты проверяют
    сборку, разбор и инъекции, но не качество обхода у конкретного
    провайдера.
13. **`capture_incoming` пока только диагностика.** Ответы сервера
    считаются и логируются, но ещё не передаются в TCP state и не меняют
    выбор стратегии автоматически.

## Требования

- Linux; архитектура не зашита.
- C11 compiler, `make`, libc с pthreads.
- `iproute2` (`ip`) и `nftables` (`nft`) для host helper.
- root или capabilities `CAP_NET_RAW` + `CAP_NET_ADMIN`.
- Для AWG: `amneziawg-tools` (`awg-quick`). `install.sh` пытается установить
  пакет автоматически; helper поднимает и опускает выбранный профиль вместе
  с RawVeil. Ключи остаются в конфиге AmneziaWG и не изменяются RawVeil.
- Для `route`-режима достаточно `ip`; для `nft`-режима нужен `nft`.

## Сборка

```sh
make              # build/rawveil
make debug        # ASan/UBSan build в build-debug/
make test         # unit + smoke tests
make debug-test   # тесты с ASan/UBSan
make netns-test   # AWG route-mode в private netns
make probe        # TLS-сегментация SoundCloud/Discord/YouTube (без root)
```

Быстрый запуск без установки:

```sh
sudo ./build/rawveil on --foreground \
  --config etc/rawveil.conf \
  --interface wlan0 \
  --send-interface wlan0 \
  --log-level debug
```

Для прямого capture на реальном интерфейсе RawVeil переотправляет кадры, но
не подавляет оригинал. Если оригинальный пакет продолжает уходить, DPI может
увидеть его; для чистой замены нужен drop/redirect hook (см. ограничения).

## Установка

```sh
sudo ./install.sh install
sudo ./install.sh start
sudo ./install.sh restart
sudo ./install.sh status
sudo ./install.sh stop
sudo ./install.sh uninstall
sudo ./install.sh reset
```

`install` собирает бинарник, устанавливает:

- `/usr/local/bin/rawveil`;
- `/usr/local/sbin/rawveil-host`;
- `/etc/rawveil/rawveil.conf`;
- `/etc/rawveil/rawveil.dpi.conf` — пресет без AWG/WARP (`--conf dpi`);
- `/etc/rawveil/lists/*.txt` — списки доменов для профилей;
- `/etc/rawveil/awg/*.conf` — профили AmneziaWG (не перезаписываются);
- `/etc/rawveil/warp_lists.txt`, `/etc/rawveil/warp_ips.txt` — большие
  списки Discord/SoundCloud/Grok для AWG;
- `/etc/default/rawveil-host` (необязательные env-переменные helper-а);
- `/etc/systemd/system/rawveil-host.service`.

`install` также пытается установить `amneziawg-tools` через `pacman`,
`apt`, `dnf` или `zypper`, а при отсутствии пакета собирает
`amneziawg-tools`/`amneziawg-go` из GitHub (если есть `git`, `make`, `cc`
и `go`). Если AWG всё равно недоступен, RawVeil продолжит работу без него.
В `/etc/default/rawveil-host` записывается
`RAWVEIL_AWG_CONFIG=/etc/rawveil/awg/default_awg.conf` — helper поднимает
этот профиль перед RawVeil и опускает его в `stop`/`cleanup`/`reset`.
Отключить автозапуск можно через `RAWVEIL_AWG_MODE=off` или пустой
`RAWVEIL_AWG_CONFIG`; `auto` следует за `[warp] enabled`.

Если `/etc/rawveil/rawveil.conf` уже существует, `install` не перезаписывает
его: добавь блок `[warp]` из [`etc/rawveil.conf`](etc/rawveil.conf) вручную
или оставь управление через `RAWVEIL_AWG_CONFIG` в
`/etc/default/rawveil-host` — helper передаст `--warp` и профиль сам.

Сервис **не включается в автозапуск**. `install` сохраняет существующий
конфиг в `/var/lib/rawveil/backups/`; `uninstall` восстанавливает его.
`stop`/`uninstall`/`reset` удаляют nft-таблицу, dummy и AWG-интерфейс,
поднятый helper-ом.

Host helper:

- определяет default uplink через `ip route`;
- создаёт dummy `rvhost0`;
- создаёт `netdev`/egress таблицу `rawveil_host`;
- пропускает короткие TCP/443 пакеты (ACK/SYN/FIN) без захвата;
- направляет TCP/443, media-порты и UDP в dummy; UDP/443 — только при
  `RAWVEIL_QUIC_MODE=fragment|fake`;
- принимает собственные кадры по маркеру `0x5256`;
- при `capture_incoming=true` открывает отдельный read-only сокет на
  uplink для ответов сервера;
- при завершении удаляет таблицу, dummy и поднятый им AWG.

Переменные окружения helper-а: `RAWVEIL_IFACE`, `RAWVEIL_CONFIG`,
`RAWVEIL_DUMMY`, `RAWVEIL_NFT_TABLE`, `RAWVEIL_FWD_MODE`, `RAWVEIL_QUIC_MODE`,
`RAWVEIL_QUIC_TABLE`, `RAWVEIL_DNS_MODE`, `RAWVEIL_DNS_TABLE`,
`RAWVEIL_DNS_PORT`, `RAWVEIL_LOG_LEVEL`, `RAWVEIL_STATE_DIR`.

`RAWVEIL_FWD_MODE=fwd` использует `fwd to dummy`; `dupdrop` использует
`dup to dummy drop` и гарантирует подавление оригинала. `RAWVEIL_QUIC_MODE`:
`pass` (QUIC идёт напрямую), `block` (ICMP reject UDP/443), `fragment`/`fake`
(forward UDP/443 в dummy и обработка RawVeil). `RAWVEIL_DNS_MODE=dot|doh`
включает DNS-прокси и nft redirect plain DNS; `off`/`system` выключают
перехват.

## CLI

```text
rawveil on [OPTIONS]        запустить демон
rawveil off [--pid-file P]  остановить демон
rawveil status [--pid-file P]
rawveil reload [--pid-file P]
rawveil --help | --version
```

Опции `on`:

| Опция | Назначение |
|---|---|
| `--config PATH` | файл конфигурации |
| `--conf PATH\|default\|dpi` | алиас конфига; `dpi` = `/etc/rawveil/rawveil.dpi.conf` без AWG |
| `--interface IFACE` | интерфейс захвата |
| `--send-interface IFACE` | интерфейс отправки; пусто = интерфейс захвата |
| `--capture-mode MODE` | `direct` или `redirect` |
| `--foreground` | не демонизироваться |
| `--warp-list PATH` | список доменов WARP |
| `--warp-ip-list PATH` | список IP/CIDR WARP |
| `--warp-iface IFACE` | интерфейс WARP/AWG |
| `--awg-config PATH` | AmneziaWG `.conf` |
| `--warp` | включить WARP/AWG-маршрутизацию на запуск |
| `--no-warp` | отключить WARP/AWG-маршрутизацию на запуск |
| `--warp-mark VALUE` | fwmark (поддерживается `0x...`) |
| `--doh-mode MODE` | `off`, `system`, `dot`, `doh` |
| `--doh-endpoint URL` | DoH endpoint |
| `--doh-bootstrap LIST` | bootstrap IPs для DoH |
| `--dns-listen ADDR` | локальный адрес DNS-прокси |
| `--dns-servers LIST` | DoT-серверы `ip#hostname,...` |
| `--profile P.K=V` | переопределить ключ профиля на один запуск |
| `--log-level LEVEL` | `debug`, `info`, `warn`, `error` |
| `--threads N` | зарезервировано |
| `--pid-file PATH` | pid-файл |
| `--stats-file PATH` | файл статистики |

Примеры:

```sh
sudo ./build/rawveil on --foreground \
  --config /etc/rawveil/rawveil.conf \
  --profile discord_tls.strategy=multisplit \
  --profile discord_tls.split_sni=true \
  --profile discord_tls.split_reverse=true \
  --profile discord_tls.desync_data_packets=64 \
  --profile discord_tls.segments=2
```

```sh
sudo ./build/rawveil reload
sudo ./build/rawveil status
sudo ./build/rawveil off
```

## Конфигурация

Формат — INI-подобные секции и пары `ключ = значение`. Комментарии начинаются
с `#` или `;`. Полный пример находится в
[`etc/rawveil.conf`](etc/rawveil.conf), списки WARP — в
[`etc/warp_ips.txt`](etc/warp_ips.txt) и
[`etc/warp_lists.txt`](etc/warp_lists.txt). Это готовые большие наборы для
Discord, SoundCloud и Grok/xAI; их можно дополнять без изменения кода.

### `[global]`

| Ключ | Назначение | Пример/default |
|---|---|---|
| `interface` | интерфейс захвата | `eth0` (укажите свой, например `wlan0`) |
| `send_interface` | интерфейс отправки; пусто = capture interface | пусто |
| `capture_mode` | `direct` или `redirect`; redirect переотправляет необработанные кадры | `redirect` |
| `capture_incoming` | read-only захват ответов сервера на uplink; счётчики TLS/QUIC в stats | `false` |
| `threads` | зарезервировано для worker pool | `4` |
| `buffer_size` | размер capture-буфера, байт | `65535` |
| `log_level` | `debug`, `info`, `warn`, `error` | `info` |
| `pid_file` | pid-файл | `/var/run/rawveil.pid` |
| `stats_file` | файл статистики | `/var/run/rawveil.stats` |

`send_interface` нужен для схемы, где захват идёт с dummy, а отправка — в
реальный uplink. Для `PACKET_OUTGOING` буфер большого размера позволяет
переотправлять крупные GSO/offloaded сегменты.

### `[tracking]`

| Ключ | Назначение | Пример |
|---|---|---|
| `tcp_timeout` | idle timeout TCP-потока, секунд | `300` |
| `udp_timeout` | idle timeout UDP-потока, секунд | `30` |
| `max_entries` | максимум записей tracker | `65536` |

### `[doh]`

| Ключ | Назначение |
|---|---|
| `enabled` | включает хранение настроек DoH |
| `mode` | реализован только `system` |
| `endpoint` | URL DoH endpoint |
| `format` | `wire` для `application/dns-message` |
| `cache_ttl` | TTL кеша DNS-прокси, секунд |
| `negative_ttl` | зарезервировано |
| `fallback_to_system` | зарезервировано; strict-режим пока не делает plaintext fallback |
| `bootstrap_ips` | IP для bootstrap DoH |
| `listen` | локальный адрес прокси, например `127.0.0.1:5353` |
| `servers` | DoT-серверы `ip#hostname,...` |
| `strict` | при ошибке DoT/DoH отдавать SERVFAIL, не plain DNS |
| `block_plain` | helper перехватывает внешний UDP/TCP 53 |
| `block_other_dot` | зарезервировано |

Секция `[dns]` — алиас `[doh]` для нового конфига. Пример:

```ini
[dns]
enabled = true
mode = dot
listen = 127.0.0.1:5353
servers = 1.1.1.1#cloudflare-dns.com,9.9.9.9#dns.quad9.net
strict = true
block_plain = true
cache_ttl = 300
```

DNS-прокси не меняет `/etc/resolv.conf` и `systemd-resolved`. Host helper
создаёт временную `inet`-таблицу `rawveil_dns` с `nat output` redirect
UDP/TCP 53 на `127.0.0.1:5353`; на `stop` таблица удаляется. Loopback
(`127.0.0.0/8`, `::1`) исключён, чтобы stub systemd-resolved продолжал
работать; его внешние запросы перехватываются.

Для DoT нужны OpenSSL (`libssl`, `libcrypto`), для DoH — libcurl. Браузерный
DoH/DoT может обходить этот proxy; для строгой защиты его нужно отключать
в браузере или блокировать известные DoH-SNI отдельно.

### Захват ответов сервера

`capture_incoming = true` открывает второй read-only AF_PACKET сокет на
`send_interface` (или на capture-интерфейсе, если `send_interface` пуст).
Он **не изменяет и не переотправляет** пакеты; в `status`/stats появляются:

```text
server_frames
server_tls
server_handshakes
server_quic
```

Это полезно для диагностики: видно, ответил ли сервер TLS ServerHello,
пошёл ли QUIC-ответ и сколько данных пришло после стратегии. Включать
постоянно не обязательно.

```sh
grep -E 'server_|incoming_' /run/rawveil-host/rawveil.stats
```

Debug-лог показывает направления ответов:

```text
server tcp 162.159.135.232:443 -> 192.168.1.20:54321 payload=...
server udp 162.159.135.232:443 -> 192.168.1.20:54322 payload=...
```

### `[warp]`

| Ключ | Назначение | Пример |
|---|---|---|
| `enabled` | включить WARP bypass; в `rawveil.dpi.conf` — `false` | `true` |
| `interface` | имя AWG-интерфейса; при `awg_config` выводится из имени файла | `default_awg` |
| `domain_list` | файл доменов, по одному на строку | `/etc/rawveil/warp_lists.txt` |
| `ip_list` | IP/CIDR-список | `/etc/rawveil/warp_ips.txt` |
| `mark` | fwmark | `0x1` |
| `bypass_strategies` | не применять стратегии к WARP-трафику | `true` |
| `awg_config` | путь к `.conf` AmneziaWG | пусто |
| `manage_routing` | управлять маршрутами/правилами | `true` |
| `routing_mode` | `route` или `nft` | `route` |
| `routing_table` | таблица для `nft`-режима | `51821` |
| `routing_priority` | priority ip rule для `nft`-режима | `1000` |

### `[security]`

| Ключ | Назначение |
|---|---|
| `drop_privileges_to` | пользователь после открытия сокетов; пусто = остаться root |
| `required_caps` | capabilities, которые сохраняются после drop |

Пользователь должен существовать до запуска. Для отправки через
`AF_PACKET` нужен как минимум `CAP_NET_RAW`; для маршрутов/правил —
`CAP_NET_ADMIN`. Файлы конфигурации и WARP-списков должны быть доступны
пользователю после drop, иначе `SIGHUP`/reload не сможет их перечитать.

## Профили стратегий

Профиль описывается секцией `[profile.NAME]`. `enabled` по умолчанию
выключен. Обязателен `strategy`; остальные значения имеют defaults.

### Фильтры

| Ключ | Значение |
|---|---|
| `enabled` | `true`/`false`; без этого профиль не компилируется |
| `filter_proto` | `tcp`, `udp`, `any` |
| `filter_ports` | порты и диапазоны: `443`, `50000-50099`, `2053,2083` |
| `filter_l7` | `tls`, `quic`, `quic_initial`, `stun`, `discord`, список через запятую |
| `filter_sni` | exact/suffix список доменов через запятую |
| `lists` | файлы списков доменов через запятую; путь относительно каталога конфига |
| `filter_lists` | алиас `lists` |
| `ip_lists` | файлы IP/CIDR-списков через запятую |
| `filter_ips` | алиас `ip_lists` |
| `filter_sni_exclude` | домены-исключения |
| `priority` | целое; больший приоритет выигрывает при пересечении профилей |

`filter_l7` — это L7-детекция. Пустое значение означает любой L7. `discord`
включает RTP и STUN. Профиль с `filter_sni`/`lists` имеет более высокий score,
чем профиль только по порту; после первого ClientHello выбранный профиль
фиксируется за потоком.

Списки доменов:

```ini
[profile.soundcloud]
lists = lists/soundcloud.txt, lists/soundcloud-extra.txt
```

Файл списка — по одному домену на строку, `#` начинает комментарий. Пути
относительны каталогу конфига, абсолютные пути тоже поддерживаются. Записи
сравниваются без учёта регистра. Поддерживаются:

- точное совпадение: `soundcloud.com`;
- suffix: `sndcdn.com` (совпадает с `i1.sndcdn.com`);
- glob: `*.soundcloud.com`, `soundcloud.*`, `*sndcdn*`, `?` для одного
  символа.

`*.soundcloud.com` не совпадает с самим `soundcloud.com` — для этого держите в
списке обе строки. Один профиль может ссылаться на несколько файлов.
Отсутствующий файл — ошибка загрузки профиля. `filter_sni` и `lists`
объединяются (достаточно совпадения одного).

IP/CIDR-списки:

```ini
[profile.discord_media]
ip_lists = lists/discord-ips.txt
```

Формат — по одному IP или CIDR на строку (`162.159.128.0/18`, `2001:db8::/32`).
IP-фильтр проверяет destination address пакета. Если в профиле одновременно
заданы доменный и IP-фильтр, должны совпасть оба условия. Это удобно для QUIC,
voice и случаев, когда SNI уже недоступен.

### Стратегии

| `strategy` | Требуемый proto | Поведение |
|---|---|---|
| `multisplit` | TCP | режет payload на `segments` сегментов |
| `fake` | любой | отправляет fake-пакеты и/или оригинал |
| `fakedsplit` | TCP | fake + multisplit |
| `fake_session` | UDP | fake-пакеты на первых пакетах потока |
| `fake_quic_initial` | UDP | fake-пакеты с QUIC Initial-like payload |
| `quic_fragment` | UDP | IP-фрагментация UDP/QUIC на IPv4/IPv6 |
| `quic_block` | UDP | не переотправлять QUIC; в helper дополнительно ICMP reject |
| `none` | любой | passthrough: переотправить оригинал без изменений |

### Параметры split/disorder

| Ключ | Default | Диапазон | Назначение |
|---|---:|---:|---|
| `split_pos` | `1` | 0..65535 | позиция разреза в payload |
| `seqovl` | `0` | 0..65535 | overlap второго сегмента |
| `segments` | `2` | 2..8 | число TCP-сегментов |
| `split_sni` | `false` | `false|start|middle|end` | где резать SNI; перекрывает `split_pos` |
| `desync_data_bytes` | `0` | 0..INT_MAX | desync только первых N байт data-фазы |
| `desync_data_start` | `0` | 0..INT_MAX | начать data-desync после N байт |
| `frag_pos` | `24` | 8..65535, кратно 8 | размер первой L4-части при `quic_fragment` |
| `frag_count` | `2` | только `2` | число IP-фрагментов |
| `frag_reverse` | `false` | bool | отправить второй фрагмент первым |
| `split_reverse` | `false` | bool | отправлять сегменты в обратном порядке |
| `split_all` | `false` | bool | применять split ко всем data-пакетам |
| `split_extra_one` | `false` | bool | дополнительный разрез на байте 1 |
| `desync_data_packets` | `0` | 0..1000000 | desync только первых N data-пакетов |
| `wssize` | `0` | 0..65535 | TCP window в исходящих пакетах; 0 = не менять |

`split_all` и `split_extra_one` агрессивны: первый может ломать потоки с
большим объёмом данных, второй меняет форму первого сегмента. Оба параметра
следует включать только после проверки на конкретном сервисе.

### Параметры fake-пакетов

| Ключ | Default | Назначение |
|---|---:|---|
| `fake_count` | `1` | число fake-пакетов, 1..16 |
| `fake_ttl` | `0` | TTL/hop limit fake-пакетов; 0 = оригинальный |
| `fake_before` | `true` | fake до (`true`) или после (`false`) реальных |
| `tcp_ack_offset` | `0` | сдвиг ACK fake-пакета |
| `fake_seq_offset` | `0` | сдвиг sequence fake-пакета; при другом payload автоматически `-10000` |
| `fake_bad_checksum` | `false` | заведомо неверная TCP/UDP checksum |
| `fake_md5sig` | `false` | TCP MD5 option в fake-пакете |
| `fake_sni` | пусто | benign SNI для fake; длина может отличаться от реальной |
| `fake_payload` | пусто | payload/fake ClientHello относительно каталога конфига |
| `session_freeze_after` | `1` | сколько первых UDP-пакетов обрабатывать |
| `fallback` | пусто | имя профиля при ошибке сборки |
| `replace_original` | `true` | переотправлять исходный payload стратегией |

`fake_payload` для UDP: если файл отсутствует, используется built-in
QUIC/STUN/RTP payload. Для TCP: если файл задан, он используется как готовый
fake ClientHello; иначе `fake_sni` пересобирает реальный ClientHello с новой
длиной SNI. Если пересборка невозможна, fake пропускается — реальный SNI в
fake не отправляется.

### Пример базового TCP-профиля

```ini
[profile.discord_tls]
enabled = true
filter_proto = tcp
filter_ports = 443
filter_l7 = tls
strategy = multisplit
split_sni = true
split_reverse = true
segments = 2
desync_data_packets = 64
replace_original = true
fallback = discord_tls_alt
```

Этот профиль режет ClientHello по SNI, отправляет сегменты в обратном
порядке и повторяет desync для первых 64 data-пакетов. Значение 64 — не
универсальный default, а параметр для подбора: при throttling после cutoff
его увеличивают, при поломке data-фазы — уменьшают или отключают.

### Пример fake-профиля

```ini
[profile.discord_tls_alt]
enabled = true
filter_proto = tcp
filter_ports = 443
filter_l7 = tls
strategy = fakedsplit
split_sni = true
split_reverse = true
segments = 2
fake_count = 1
fake_ttl = 2
fake_before = true
fake_sni = example.com
fake_seq_offset = -10000
replace_original = true
```

Fake-параметры экспериментальные. Если handshake перестаёт проходить,
сначала отключают `fake_md5sig`/`fake_bad_checksum`/`fake_seq_offset`, затем
уменьшают `fake_count`, и только после этого меняют split.

### Пример UDP-профиля

```ini
[profile.discord_voice]
enabled = true
filter_proto = udp
filter_ports = 50000-50099
filter_l7 = discord,stun
strategy = fake_session
fake_count = 6
fake_ttl = 1
session_freeze_after = 3
replace_original = true
```

### QUIC/HTTP3

`quic_fragment` режет UDP-датаграмм на два IP-фрагмента. Первый содержит UDP
заголовок и `frag_pos - 8` байт QUIC; `frag_pos` должен быть кратен 8.
UDP checksum не пересчитывается: он покрывает весь датаграмм. Для IPv6
добавляется Fragment extension header.

```ini
[profile.quic_fragment]
enabled = true
filter_proto = udp
filter_ports = 443
filter_l7 = quic_initial
strategy = quic_fragment
frag_pos = 24
frag_count = 2
replace_original = true
```

`quic_block` не переотправляет QUIC и заставляет клиент уйти на TCP. В host
helper для этого есть `RAWVEIL_QUIC_MODE=block`, который ставит `inet`-правило
`reject with icmp/icmpv6 port-unreachable` (не NFQUEUE). Если нужно наоборот
пропускать QUIC напрямую, используйте `RAWVEIL_QUIC_MODE=pass` (default).

Пример per-SNI профиля:

```ini
[profile.youtube_tls]
enabled = true
filter_proto = tcp
filter_ports = 443
filter_l7 = tls
filter_sni = youtube.com,googlevideo.com,ytimg.com,ggpht.com
strategy = multisplit
split_sni = start
split_reverse = false
desync_data_bytes = 65536
replace_original = true
```

При `split_sni=start` используйте `split_reverse=false`, иначе первым уйдёт
сегмент, начинающийся с hostname. `split_sni=middle` можно сочетать с
`split_reverse=true`.

`track_connections` в примерах конфигурации зарезервирован и в текущей
версии не влияет на engine.

## AWG/WARP

RawVeil не реализует WireGuard/AmneziaWG handshake и не меняет ключи.
Host helper (`rawveil-host`) автоматически поднимает выбранный профиль
`awg-quick` и **гарантированно опускает его** при `stop`, `cleanup`,
`uninstall`, `reset`, завершении сервиса или падении RawVeil. Для
split-маршрутизации helper готовит runtime-копию конфига с `Table = off`
и без `DNS`, поэтому `awg-quick` не затирает default route и
systemd-resolved.

Helper также проверяет, что AWG не поставила default route, и защищает
маршрут до endpoint туннеля через физический uplink. При обнаружении
route leak AWG аварийно опускается и RawVeil продолжает работу без туннеля.
`install.sh` устанавливает `amneziawg-tools`, копирует профили из
[`etc/awg/`](etc/awg) в `/etc/rawveil/awg/` (существующие файлы не
перезаписываются) и прописывает
`RAWVEIL_AWG_CONFIG=/etc/rawveil/awg/default_awg.conf` в
`/etc/default/rawveil-host`. Доступны 10 профилей; `default_awg.conf`
используется по умолчанию. Выбрать другой:

```sh
sudo sed -i 's#^RAWVEIL_AWG_CONFIG=.*#RAWVEIL_AWG_CONFIG=/etc/rawveil/awg/warp3.conf#' \
    /etc/default/rawveil-host
sudo ./install.sh restart   # или systemctl restart rawveil-host
```

Пример `[warp]` (helper сам передаст `--warp` и путь к профилю):

```ini
[warp]
enabled = true
awg_config = /etc/rawveil/awg/default_awg.conf
interface = default_awg
domain_list = /etc/rawveil/warp_lists.txt
ip_list = /etc/rawveil/warp_ips.txt
manage_routing = true
routing_mode = route
mark = 0x1
```

Ручной запуск без helper:

```sh
sudo awg-quick up /etc/rawveil/awg/default_awg.conf
sudo ./build/rawveil on --foreground --warp \
  --awg-config /etc/rawveil/awg/default_awg.conf \
  --config /etc/rawveil/rawveil.conf
ip route show proto 247
sudo awg-quick down default_awg   # RawVeil не останавливает чужой AWG
```

### Режим без AWG/WARP

Для чистой проверки DPI-стратегий без туннеля есть отдельный пресет:

```sh
sudo ./install.sh install
sudo ./build/rawveil on --foreground --conf dpi
```

`dpi` указывает на `/etc/rawveil/rawveil.dpi.conf`, где:

```ini
[warp]
enabled = false
awg_config =
manage_routing = false
```

`interface` в конфиге должен существовать. В `rawveil.dpi.conf` для этого
хоста указан `wlan0`; при запуске через `rawveil-host` uplink определяется
автоматически, а `rawveil` получает `--interface rvhost0` и
`--send-interface wlan0`.

`rawveil-host` с `RAWVEIL_AWG_MODE=auto` (по умолчанию) читает
`[warp] enabled` из выбранного конфига и **не поднимает AWG**, если там
`false`. Принудительно:

```sh
RAWVEIL_AWG_MODE=off sudo ./install.sh start
# или
sudo RAWVEIL_CONFIG=/etc/rawveil/rawveil.dpi.conf \
  /usr/local/sbin/rawveil-host run
```

Для возврата AWG:

```sh
RAWVEIL_AWG_MODE=on sudo ./install.sh restart
```

Режимы:

- `route` — для каждого IP/CIDR из списков добавляется маршрут через AWG
  с меткой `proto 247`. Нужен только `ip`. Stale-маршруты `proto 247`
  удаляются на старте и при остановке. После `SIGHUP` маршруты
  пересобираются.
- `nft` — nftables set + `meta mark` + `ip rule fwmark ... lookup
  routing_table` + default route в отдельной таблице. Нужен `nft`.

Готовые списки [`etc/warp_lists.txt`](etc/warp_lists.txt) и
[`etc/warp_ips.txt`](etc/warp_ips.txt) покрывают Discord, SoundCloud и
Grok/xAI (Cloudflare + CloudFront). Домены разрешаются системным
resolver-ом при загрузке и `reload`; IP/CIDR не требуют DNS. Если
`AllowedIPs` туннеля не включает нужные адреса, маршрут будет создан, но
трафик может не пройти. Проверка:

```sh
ip route get 162.159.136.232   # должен показать dev default_awg
ip route get 142.250.72.14     # YouTube должен остаться на wlan0
```

WARP-трафик при `bypass_strategies=true` не проходит через DPI-стратегии.
Это позволяет использовать туннель как отдельный путь для проблемных
доменов, не смешивая его с SNI-фрагментацией.

## Тестирование

```sh
make test
make debug-test
make netns-test
```

### Проверка сегментации TLS на реальных endpoints

Безопасный вспомогательный тест не меняет маршруты, nftables или DNS. Он
поднимает локальный TCP-relay, получает настоящий ClientHello от `openssl`
и отправляет его в нескольких вариантах сегментации:

```sh
python3 tools/strategy_probe.py soundcloud.com discord.com www.youtube.com
python3 tools/strategy_probe.py --json api-v2.soundcloud.com
```

Режимы: `baseline`, `tcp_chunks`, `sni_start`, `sni_middle`, `sni_end`,
`record_split`. Тест показывает, принимает ли endpoint конкретный вариант;
он не определяет DPI провайдера и не заменяет проверку приложения.

Локальный прогон на тестовом маршруте показал:

- SoundCloud и Discord: все варианты проходят;
- YouTube: `sni_start` и `record_split` зависали, а `sni_middle`,
  `sni_end` и обычная отправка проходили;
- `youtubei.googleapis.com` не устанавливал TCP-соединение — это
  IP/сетевой блок, для него TLS-фрагментация не поможет и нужен отдельный
  fallback/маршрут, если он разрешён.

Поэтому для YouTube в примере конфигурации включён отдельный
`youtube_tls` с `split_sni = middle`.

- `tests/bpf_test.c` — classic BPF через userspace-интерпретатор:
  IPv4/IPv6, VLAN, TLS/media-порты, UDP-диапазон, фрагменты, короткие кадры.
- `tests/tls_test.c` — ClientHello/SNI, пересборка SNI с другой длиной,
  неполный record, application data, отсутствие extensions, некорректные
  длины.
- `tests/quic_test.c` — QUIC Initial/Version Negotiation/short header,
  усечённые заголовки.
- `tests/netbuild_test.c` — IPv4/TCP с options и IPv6/UDP, checksum, маркер,
  seq/ack, длины, padding и IPv4/IPv6 IP-фрагменты.
- `tests/tracker_test.c` — создание/повтор потока, flags, timeouts, лимит
  записей, очистка.
- `tests/engine_test.c` — offline-движок без `CAP_NET_RAW`: профили,
  multisplit, повторная переотправка, UDP fake_session/freeze, счётчики.
- `tests/awg_test.c` — парсинг `.conf`: interface из имени файла, Address,
  AllowedIPs, MTU, Table, FwMark.
- `tests/routing_test.c` — `route`/`nft` через подставные `ip`/`nft`:
  маршруты, mark-правила, set elements и cleanup.

`tests/smoke_test.sh` выполняет CLI/config-проверки, затем пытается войти в
`unshare -Urn`. В private netns поднимается `lo`, запускается RawVeil с
профилем `multisplit`, генерируются TCP 443/80, UDP 443/50000/50099/
49999/50100 и настоящий TLS ClientHello. Проверяются логи стратегии,
WARP-обработка, `status`/`off` и счётчики `strategy_applied`,
`strategy_injected_frames`, `injected_ignored`.

Если unprivileged namespaces недоступны, capture-часть пропускается. Тест не
запускается на реальном интерфейсе и не является проверкой обхода DPI.

Ручной запуск smoke-теста:

```sh
sudo unshare -Urn sh -c 'ip link set lo up; ./tests/smoke_test.sh'
```

Проверка AWG route-mode с dummy `awg0`:

```sh
make netns-test
```

`tests/netns_awg_route_test.sh` создаёт dummy `awg0`, запускает RawVeil с
синтетическим `awg0.conf`, проверяет `ip route show proto 247`,
`ip route get 1.2.3.4` → `dev awg0` и очистку маршрутов после `off`.

### Текущее состояние проверки

- `make test`: unit-тесты и безопасные CLI/config-проверки проходят; smoke
  capture-часть выполняется только при доступных private netns.
- `make netns-test`: проверяет AWG route-mode на dummy-интерфейсе.
- Offline engine-тесты не требуют root и не трогают сеть.
- Реальный обход DPI не входит в автоматические тесты: результат зависит от
  ISP, DPI, CDN и endpoint. Успешный handshake, HTTP/2-ответ или загрузка
  одного файла не означают, что сервис работает полностью.
- Проверка «работает/не работает» для конкретного сервиса должна включать
  TLS handshake, API/WebSocket, assets и data-фазу, а не только HTTP-код
  главной страницы.

## Безопасность

RawVeil работает с raw-сокетами и меняет сетевые правила. Запуск выполняется
только от root или с явно выданными capabilities.

- После открытия сокетов процесс может сбросить privileges до
  `drop_privileges_to` и сохранить только `required_caps`.
- Host helper изменяет nftables и создаёт dummy; таблица и интерфейс
  удаляются при штатной остановке и по `ExecStopPost`.
- При аварийном завершении helper-а возможны остаточные объекты; `stop`,
  `cleanup` и `reset` удаляют их.
- Не рекомендуется оставлять nftables-таблицу постоянной: это меняет
  маршрут пакетов даже без запущенного RawVeil.
- Конфигурация и WARP-списки должны быть доступны только доверенным
  пользователям: они влияют на маршрутизацию и содержимое отправляемых
  пакетов.
- Профили `/etc/rawveil/awg/*.conf` содержат приватные ключи и
  устанавливаются с правами `0600`; helper создаёт runtime-копию в
  `/run/rawveil-host/awg/` также с `0600`. Не публикуйте эти файлы в
  репозитории/архивах.
- Проект не является средством обхода каких-либо ограничений сам по себе;
  применение должно соответствовать правилам сети и законодательству.

## Диагностика

Проверить состояние:

```sh
sudo ./install.sh status
sudo rawveil status --pid-file /run/rawveil-host/rawveil.pid
sudo nft list table netdev rawveil_host
ip link show rvhost0
ip route show proto 247
```

Логи:

```sh
sudo journalctl -u rawveil-host -f
```

Признаки в логах:

- `profile ...: strategy=...` — профиль скомпилирован;
- `strategy multisplit ...` — стратегия применена;
- `warp match ... bypassing strategies` — поток ушёл в WARP;
- `routing: ...` — созданы/удалены маршруты;
- `strategy send failed` / `strategy build failed` — проблема сборки или TX.

Типичные причины отсутствия эффекта:

1. Профиль не совпал по `filter_proto`, `filter_ports` или `filter_l7`.
2. Пакет не дошёл до capture: nft-правило не создано или оригинал дропнут
   раньше `PACKET_OUTGOING`.
3. Стратегия применилась, но DPI reassembling-ит TCP.
4. Оригинальный пакет не подавлен и DPI видит его вместо/вместе с
   пересобранными сегментами.
5. Блокировка происходит по IP/CDN, а не по SNI.
6. `fake_*`/`split_*` параметры ломают handshake; нужен откат к базовому
   `multisplit + split_sni + split_reverse`.

## Структура

```text
include/          публичные заголовки модулей
src/main.c        CLI, команды, сигналы, основной цикл, reload, stats
src/config.c      INI-парсер, профили, defaults/validation
src/daemon.c      daemonize, drop privileges, pid-файл, stats-файл
src/capture.c     AF_PACKET capture, recvmmsg, логи, WARP bypass
src/packet.c      разбор Ethernet/VLAN/IP/TCP/UDP
src/bpf_filter.c  генератор classic BPF-фильтра
src/l7.c          TLS/QUIC/STUN/RTP detection
src/tls_parser.c  ClientHello + SNI
src/tracker.c     connection tracking, таймауты, freeze
src/netbuild.c    сборка IPv4/IPv6 TCP/UDP кадров + checksum
src/sender.c      AF_PACKET TX + sendmmsg
src/strategies.c  профили, multisplit/fake/fakedsplit, engine
src/warp.c        WARP IP/CIDR/domain-списки, хэш-таблица, hot reload
src/awg.c         парсер AmneziaWG .conf
src/routing.c     route/nft WARP routing через awg0
src/log.c         уровни, stderr/syslog, потокобезопасность
scripts/          host helper
tools/            strategy_probe.py (безопасный live-probe TLS-сегментации)
tests/            unit, engine, AWG, routing, smoke, netns
etc/              пример конфига, DPI-пресет и WARP-списки
```

## Планы

1. ~~Захват ответов сервера~~ — read-only `capture_incoming` уже есть; ещё
   нужно использовать входящие пакеты в TCP state (retransmit/ACK/ServerHello).
2. Периодический refresh WARP DNS/IP без `SIGHUP`; расширение DNS-прокси
   (negative cache, DoH HTTP/2 fallback, блокировка чужих DoT/DoH).
3. Пул capture/strategy workers с `PACKET_FANOUT` и affinity.
4. Динамический BPF по портам из профилей.
5. IPv6 extension headers, QUIC Initial с валидным TLS-фрагментом, более
   точные fake-пакеты.
6. Drop/redirect hook до `dev_queue_xmit` (eBPF tc egress или аналог),
   чтобы строго соблюсти схему «оригинал подавлен, RawVeil пересобирает».
7. Расширенные стратегии: disorder, oob, TLS record fragmentation,
   per-connection state machine.
8. Автоматическая проверка набора стратегий на тестовом endpoint с
   сохранением рабочей конфигурации; базовый `tools/strategy_probe.py` уже
   добавлен.
