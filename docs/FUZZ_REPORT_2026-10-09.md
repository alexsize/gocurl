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
P0 воспроизводимости закрыт локальной фиксацией и чистым checkout ниже.
Следующий P1 приоритет — исчерпывающая API/CLI parity (пункт 5); свежий CI
и межплатформенные результаты пункта 7 ещё не подтверждены.
Push, GitHub release и новая версия не выполнялись.

Обновлены README, AGENTS, CHANGELOG и ТЗ: исправлены body framing duplication,
QUIC ACK/payload examples, HRR report semantics и local/opt-in test policy.
Флаги, публичный API и JSON Schema не расширялись.

## Фиксация и чистый checkout

После staged GitNexus analysis (CRITICAL для всего накопленного scope:
1833 изменённых символа, 194 затронутых потока) пользователь явно разрешил
checkpoint всего набора в `main`. Создан локальный коммит
`93420270cb49a0ecd908fd38bf29c1e2df4ef68d`: 2077 изменённых файлов, включая
1922 файла vendor. Всего Git отслеживает 2090 файлов; untracked source files
после фиксации отсутствуют. Новые ветки, gitlink и релизный тег не создавались.
В собственных кандидатах не найдены распространённые token/private-key
literals; это целевая проверка, не гарантия обнаружения любого секрета.
Среди staged paths нет локальных баз, ключей, captures и бинарников.
Upstream whitespace в vendor не переписывался; собственные файлы прошли
`git diff --cached --check` без замечаний. Git нормализовал CRLF в index,
не меняя семантику исходников.

Создан независимый local clone `main` с отключённым CRLF-преобразованием:

```text
C:\Users\Alex\AppData\Local\Temp\gocurl-release-20261009-a6f29b256ca14c47a4e0444a9243923c
```

Из этого checkout прошёл полный `scripts/check.ps1` на Go 1.26.6/Windows
amd64, включая race suite с benchmarks и vendored QUIC wire tests.
Маркер: `CLEAN_CHECKOUT_GATE_PASS`. После gate
`git status --porcelain=v1 --untracked-files=all` пустой.
Проверка использует установленный toolchain, lint/Node и обычный module cache;
она не заявляет offline build на машине с пустым dependency cache.
Временный clone сохранён для воспроизведения и не включён в исходники.

Корневой JA3Proxy — отдельный репозиторий: его накопленные изменения данным
коммитом не фиксировались. Его fidelity-отчёт дополнен результатами ранее
завершённых проверок, но чистый checkout основного проекта пока не подтверждён.
