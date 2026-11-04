# RawVeil

RawVeil — экспериментальный демон для Linux, который перехватывает исходящий
трафик через `AF_PACKET`, разбирает TLS/QUIC/STUN/RTP, применяет стратегии
фрагментации и переотправляет изменённые кадры через `AF_PACKET` +
`sendmmsg`. Проект не использует NFQUEUE и не является форком zapret,
GoodbyeDPI или аналогичных проектов.

Основная задача — исследовать и воспроизводить поведение DPI на уровне
L2–L4: разрезать TLS ClientHello, менять порядок сегментов, добавлять
fake-пакеты, управлять TCP window и маршрутизировать выбранные адреса через
AmneziaWG/WARP.

> **Статус:** инженерный прототип, не production-ready. Поведение зависит от
> конкретного DPI, сети и удалённого endpoint. Успешный TLS handshake не
> гарантирует нормальную передачу данных.

## Содержание

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
- Безопасный разбор Ethernet/VLAN/IPv4/IPv6/TCP/UDP с проверкой длин.
- Разбор TLS ClientHello и SNI, QUIC long header, STUN magic cookie, RTP.
- Connection tracking с таймаутами, лимитом записей и freeze для UDP.
- Пересборка IPv4/IPv6 TCP/UDP, TCP options, checksum, нарезка по MTU.
- Защита от повторного захвата собственных кадров: IPv4 ID / IPv6 flow
  label `0x5256`.
- Стратегии `multisplit`, `fake`, `fakedsplit`, `fake_session`,
  `fake_quic_initial` и fallback-профиль.
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
| UDP/STUN/RTP/QUIC Initial | только fake-инъекции | полноценный QUIC handshake не реализован |
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
   handshake. `fake_sni` заменяет SNI только при совпадении длины.
6. **nftables `PACKET_OUTGOING`.** Классический AF_PACKET tap срабатывает
   после netfilter `OUTPUT`/`POSTROUTING`. Если оригинал дропается до
   `dev_queue_xmit`, RawVeil его не увидит.
7. **Host helper не является универсальным firewall.** Он создаёт
   `netdev`-таблицу с `fwd to` dummy и удаляет её при остановке. Схема
   рассчитана на тестирование и не заменяет продуманный egress-hook.
8. **`threads` зарезервирован.** Используется один capture reader; worker
   pool и `PACKET_FANOUT` ещё не реализованы.
9. **`[doh] mode=system`.** Встроенный DoH-клиент отсутствует; домены
   WARP-списков разрешаются системным resolver-ом.
10. **Нет per-domain профилей.** Нельзя назначить отдельную стратегию для
    `youtube.com`, `discord.com` и `cdn.discordapp.com` в одном процессе.
11. **Нет автоматического обновления WARP-списков.** После изменения
    списков нужен `SIGHUP`/`reload`.
12. **Тесты не воспроизводят реальный DPI.** Unit/smoke-тесты проверяют
    сборку, разбор и инъекции, но не качество обхода у конкретного
    провайдера.

## Требования

- Linux; архитектура не зашита.
- C11 compiler, `make`, libc с pthreads.
- `iproute2` (`ip`) и `nftables` (`nft`) для host helper.
- root или capabilities `CAP_NET_RAW` + `CAP_NET_ADMIN`.
- Для AWG: установленный AmneziaWG и поднятый интерфейс (`awg-quick` или
  systemd). RawVeil не запускает туннель и не управляет ключами.
- Для `route`-режима достаточно `ip`; для `nft`-режима нужен `nft`.

## Сборка

```sh
make              # build/rawveil
make debug        # ASan/UBSan build в build-debug/
make test         # unit + smoke tests
make debug-test   # тесты с ASan/UBSan
make netns-test   # AWG route-mode в private netns
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
sudo ./install.sh status
sudo ./install.sh stop
sudo ./install.sh uninstall
sudo ./install.sh reset
```

`install` собирает бинарник, устанавливает:

- `/usr/local/bin/rawveil`;
- `/usr/local/sbin/rawveil-host`;
- `/etc/rawveil/rawveil.conf`;
- `/etc/systemd/system/rawveil-host.service`.

Сервис **не включается в автозапуск**. `install` сохраняет существующий
конфиг в `/var/lib/rawveil/backups/`; `uninstall` восстанавливает его.
`stop`/`uninstall`/`reset` удаляют nft-таблицу и dummy.

Host helper:

- определяет default uplink через `ip route`;
- создаёт dummy `rvhost0`;
- создаёт `netdev`/egress таблицу `rawveil_host`;
- пропускает короткие TCP/443 пакеты (ACK/SYN/FIN) без захвата;
- направляет TCP/443, media-порты и UDP в dummy;
- принимает собственные кадры по маркеру `0x5256`;
- при завершении удаляет таблицу и dummy.

Переменные окружения helper-а: `RAWVEIL_IFACE`, `RAWVEIL_CONFIG`,
`RAWVEIL_DUMMY`, `RAWVEIL_NFT_TABLE`, `RAWVEIL_LOG_LEVEL`,
`RAWVEIL_STATE_DIR`.

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
| `--interface IFACE` | интерфейс захвата |
| `--send-interface IFACE` | интерфейс отправки; пусто = интерфейс захвата |
| `--foreground` | не демонизироваться |
| `--warp-list PATH` | список доменов WARP |
| `--warp-ip-list PATH` | список IP/CIDR WARP |
| `--warp-iface IFACE` | интерфейс WARP/AWG |
| `--awg-config PATH` | AmneziaWG `.conf` |
| `--warp-mark VALUE` | fwmark (поддерживается `0x...`) |
| `--doh-mode MODE` | реализован только `system` |
| `--doh-endpoint URL` | сохраняется, но не используется в `mode=system` |
| `--doh-bootstrap LIST` | сохраняется |
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
[`etc/warp_ips.txt.example`](etc/warp_ips.txt.example) и
[`etc/warp_lists.txt.example`](etc/warp_lists.txt.example).

### `[global]`

| Ключ | Назначение | Пример/default |
|---|---|---|
| `interface` | интерфейс захвата | `eth0` |
| `send_interface` | интерфейс отправки; пусто = capture interface | пусто |
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
| `endpoint` | URL DoH; сохраняется, но не используется |
| `format` | сохраняется |
| `cache_ttl` | сохраняется |
| `fallback_to_system` | использовать системный resolver |
| `bootstrap_ips` | сохраняется |

В текущей версии домены из WARP-списков разрешаются через системный
`getaddrinfo()`. Встроенный DoH/DoT-клиент не реализован.

### `[warp]`

| Ключ | Назначение | Пример |
|---|---|---|
| `enabled` | включить WARP bypass | `true` |
| `interface` | имя AWG-интерфейса; при `awg_config` выводится из имени файла | `awg0` |
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
| `filter_l7` | `tls`, `quic`, `stun`, `discord`, список через запятую |

`filter_l7` — это L7-детекция, а не SNI-фильтр. Пустое значение означает
любой L7. `discord` включает RTP и STUN.

### Стратегии

| `strategy` | Требуемый proto | Поведение |
|---|---|---|
| `multisplit` | TCP | режет payload на `segments` сегментов |
| `fake` | любой | отправляет fake-пакеты и/или оригинал |
| `fakedsplit` | TCP | fake + multisplit |
| `fake_session` | UDP | fake-пакеты на первых пакетах потока |
| `fake_quic_initial` | UDP | fake-пакеты с QUIC Initial-like payload |

### Параметры split/disorder

| Ключ | Default | Диапазон | Назначение |
|---|---:|---:|---|
| `split_pos` | `1` | 0..65535 | позиция разреза в payload |
| `seqovl` | `0` | 0..65535 | overlap второго сегмента |
| `segments` | `2` | 2..8 | число TCP-сегментов |
| `split_sni` | `false` | bool | резать в середине SNI; перекрывает `split_pos` |
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
| `fake_ttl` | `1` | TTL/hop limit fake-пакетов; 0 = оригинальный |
| `fake_before` | `true` | fake до (`true`) или после (`false`) реальных |
| `tcp_ack_offset` | `0` | сдвиг ACK fake-пакета |
| `fake_seq_offset` | `0` | сдвиг sequence fake-пакета, например `-10000` |
| `fake_bad_checksum` | `false` | заведомо неверная TCP checksum |
| `fake_md5sig` | `false` | TCP MD5 option в fake-пакете |
| `fake_sni` | пусто | benign SNI для fake; длина должна совпадать с реальной |
| `fake_payload` | пусто | файл payload относительно каталога конфига |
| `session_freeze_after` | `1` | сколько первых UDP-пакетов обрабатывать |
| `fallback` | пусто | имя профиля при ошибке сборки |
| `replace_original` | `true` | переотправлять исходный payload стратегией |

`fake_payload` для UDP: если файл отсутствует, используется built-in
QUIC/STUN/RTP payload. Для TCP fake-пакета используется копия payload
ClientHello; `fake_sni` заменяет SNI только при совпадении длины.

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

`track_connections` в примерах конфигурации зарезервирован и в текущей
версии не влияет на engine.

## AWG/WARP

RawVeil не запускает `awg-quick`, не управляет ключами и не реализует
WireGuard/AmneziaWG handshake. Он читает `.conf`, проверяет интерфейс и
направляет выбранные IP в уже поднятый AWG-интерфейс.

```ini
[warp]
enabled = true
awg_config = /etc/amnezia/amneziawg/awg0.conf
interface = awg0
domain_list = /etc/rawveil/warp_lists.txt
ip_list = /etc/rawveil/warp_ips.txt
manage_routing = true
routing_mode = route
mark = 0x1
```

```sh
sudo awg-quick up awg0
sudo ./build/rawveil on --foreground --config /etc/rawveil/rawveil.conf
ip route show proto 247
```

Режимы:

- `route` — для каждого IP/CIDR из списков добавляется маршрут через `awg0`
  с меткой `proto 247`. Нужен только `ip`. Stale-маршруты `proto 247`
  удаляются на старте и при остановке. После `SIGHUP` маршруты
  пересобираются.
- `nft` — nftables set + `meta mark` + `ip rule fwmark ... lookup
  routing_table` + default route в отдельной таблице. Нужен `nft`.

Для split-WARP в AWG-конфиге нужен `Table = off`. При `Table = auto`
`awg-quick` может завернуть весь трафик, и списки RawVeil перестанут быть
единственным критерием.

Домены из `warp_lists.txt` разрешаются системным resolver-ом при загрузке и
reload. Если `AllowedIPs` туннеля не включает нужные адреса, маршрут будет
создан, но трафик может не пройти.

WARP-трафик при `bypass_strategies=true` не проходит через DPI-стратегии.
Это позволяет использовать туннель как отдельный путь для проблемных
доменов, не смешивая его с SNI-фрагментацией.

## Тестирование

```sh
make test
make debug-test
make netns-test
```

- `tests/bpf_test.c` — classic BPF через userspace-интерпретатор:
  IPv4/IPv6, VLAN, TLS/media-порты, UDP-диапазон, фрагменты, короткие кадры.
- `tests/tls_test.c` — ClientHello/SNI, неполный record, application data,
  отсутствие extensions, некорректные длины.
- `tests/netbuild_test.c` — IPv4/TCP с options и IPv6/UDP, checksum, маркер,
  seq/ack, длины и padding.
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
tests/            unit, engine, AWG, routing, smoke, netns
etc/              пример конфига и WARP-списков
```

## Планы

1. Per-SNI/per-domain профили: выбор стратегии по имени хоста и отдельные
   наборы параметров для разных сервисов.
2. Захват ответов сервера (аналог `PKT_IN`) и учёт входящих пакетов в
   состоянии TCP.
3. Встроенный DoH и периодический refresh WARP DNS/IP без `SIGHUP`.
4. Пул capture/strategy workers с `PACKET_FANOUT` и affinity.
5. Динамический BPF по портам из профилей.
6. IPv6 extension headers, QUIC Initial с валидным TLS-фрагментом, более
   точные fake-пакеты.
7. Drop/redirect hook до `dev_queue_xmit` (eBPF tc egress или аналог),
   чтобы строго соблюсти схему «оригинал подавлен, RawVeil пересобирает».
8. Расширенные стратегии: disorder, oob, TLS record fragmentation,
   per-connection state machine.
9. Автоматическая проверка набора стратегий на тестовом endpoint с
   сохранением рабочей конфигурации.
