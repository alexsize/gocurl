# Парсеры HTTP/2, QUIC и TLS-профилей — 9 октября 2026

## Результат

Продолжен пункт 8 единого backlog. Добавлены семь fuzz-targets. Исправлен
SOCKS UDP address helper: `Atoi` принимал −1, 65536 и 99999 как порты без
ошибки. Регрессионный тест воспроизвёл все три случая до исправления.
Теперь helper возвращает ошибку и nil address для портов вне 0..65535.
Нулевой порт, корректные IPv4/IPv6 и remote DNS semantics сохранены.
Это исправление конкретного helper, не утверждение, что все прежние
публичные маршруты отправляли такие порты по сети.

## Покрытие

| Target | Проверки | Входов за короткий прогон |
| --- | --- | --- |
| `FuzzHTTP2SettingsBounds` | Пустые defaults, границы uint32/frame size, отрицательные значения и переполнение; ошибка не возвращает частичные SETTINGS | 417066 |
| `FuzzHTTP2Orders` | Порядок и уникальность SETTINGS/pseudo-headers, допустимые имена, colon/case/whitespace rules | 261345 |
| `FuzzQUICTransportParameterOrder` | uint62, mixed decimal/hex, дубликаты, сохранение порядка, canonical round trip | 466139 |
| `FuzzQUICTransportNumericOptions` | 15 параметров, duration/stream/packet/CID bounds, explicit zero, неизменность input и canonical round trip | 479582 |
| `FuzzSOCKSUDPRemoteAddress` | IPv4/IPv6/domain, local/remote DNS, синтаксис и диапазон порта; без DNS или dial | 326254 |
| `FuzzDecodeClientProfile` | JSON decode/validation, canonical round trip и вызов materializer; неподдержанный профиль не обязан материализоваться | 115891 |
| `FuzzProfileConstraints` | JSON Pointer escapes, present/equals/one_of, обязательные значения и malformed JSON | 121130 |

Каждый target запускался отдельно с `-fuzztime=20s -parallel=2`.
Сумма: 2187407 входов, без сбоев после исправления. Время завершения некоторых
прогонов около 21 секунды из-за завершения workers. Ограничение входа в тестах
8 KiB (64 KiB для profile JSON) не добавляет ограничений в production parser.

## Проверки

Go 1.26.6, Windows amd64, golangci-lint 2.10.1. После изменений прошли
штатный `scripts/check.ps1`, markdownlint, полный lint с 0 замечаний, mod verify,
vet, полный race suite с benchmarks, all-package build и отдельные vendored
QUIC wire tests. Целевой race suite config/proxy/utlsengine также прошёл.

Пример повторения одного target из корня goCURL:

```powershell
go test -mod=vendor ./internal/config -run='^$' -fuzz='^FuzzHTTP2Orders$' -fuzztime=20s -parallel=2
```

Profile targets находятся в `./internal/client/utlsengine`, SOCKS target —
в `./internal/client/proxy`. Fuzz seed corpora выполняются и при обычном
`go test ./...`; полноценная генерация требует явного `-fuzz`.

## Границы и следующий приоритет

Короткие прогоны не доказывают отсутствие всех ошибок. Пункт 8 остаётся
частичным до длительных прогонов и аудита непокрытых критичных ветвей.
Это не полный fuzz QUIC-стека или arbitrary HTTP/2 frame replay.
Следующий P0/P1 приоритет: все исходники и vendored patch должны быть
зафиксированы в собственном main goCURL, затем проверены из чистого checkout
и свежим CI. Локальный успешный gate не равен выполнению этих требований.
API/CLI parity остаётся частичной по критериям текущего ТЗ. Коммит, push,
GitHub release и новая версия данным отчётом не подтверждаются.

Обновлены README, AGENTS, CHANGELOG и ТЗ: исправлены body framing duplication,
QUIC ACK/payload examples, HRR report semantics и local/opt-in test policy.
Флаги, публичный API и JSON Schema не расширялись.
