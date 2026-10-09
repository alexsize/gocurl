# Техническое задание: расширение gocurl для JA3Proxy

- Редакция: 2.2
- Дата последнего дополнения: 2026-10-09 (исходный аудит: 2026-09-29)
- Статус: рабочее ТЗ и аудит текущей реализации
- Целевая база: форк gocurl, работа ведётся в `main`
- Схема TLS-профиля: `ja3proxy-client-profile/1`

## 1. Назначение и обещания продукта

gocurl должен позволять формировать HTTP-запросы и выбирать документированные
TLS/HTTP/2/HTTP/3 параметры профиля из CLI или Go API. Там, где это возможно,
он проверяет именно отправленные байты либо значения, увиденные локальным
приёмником. Отчёт обязан различать:

1. что было запрошено конфигурацией;
2. что библиотека смогла сформировать;
3. что фактически было наблюдено на соединении;
4. что осталось неподдержанным или не наблюдалось.

Термины «полный отпечаток», «точное воспроизведение» и «совпадение» разрешены
только для явно перечисленных полей и подтверждённых capture-тестом режимов.
Ни одна комбинация настроек не обещает побайтовое совпадение произвольного
браузера целиком.

## 2. Границы

- JA3/JA4 — признаки TLS ClientHello. HTTP-заголовки, HTTP/2 framing и QUIC
  transport parameters — отдельные уровни и отдельные результаты проверки.
- Через обычный HTTP CONNECT target ClientHello формирует gocurl; прокси
  пересылает TLS-поток. При MITM существуют две TLS-сессии, и каждый отпечаток
  относится только к своему плечу.
- TLS к HTTPS-прокси и TLS к target настраиваются и отчётируются независимо.
- При ECH наблюдаемый снаружи ClientHello не раскрывает внутренний ClientHello.
- OHTTP защищает запрос к gateway; отчёт соединения не описывает скрытый
  target.
- TCP/IP, JA4T, расписание пакетов ОС и сетевой стек не являются отпечатками,
  которыми управляет gocurl.
- HTTP/3 использует QUIC. ClientHello извлекается из TLS handshake bytes,
  переданных в QUIC Initial CRYPTO stream; профиль проверяется по этому
  сообщению после успешной записи исходящего UDP-пакета. Это не означает
  управления произвольными QUIC-пакетами.

## 3. Подтверждённый функционал на дату аудита

Статус ниже основан на исходниках, тестах и документации репозитория; это не
утверждение о побайтовом совпадении с произвольной реализацией.

| Область | Реализовано | Ограничение / остаток |
| --- | --- | --- |
| HTTP-запрос | CLI и публичный Go API; методы, URL, повторяемые заголовки, файл/stdin и бинарное тело, proxy routing, `Resolve`, выбор IP-семейства и DNS upstream’ов, `ConnectTo` с сохранением URL/Host/SNI, `ConnectTimeout`, OHTTP через пару gateway/keys URL; автоматические redirect/retry отключены и проверены | Повторное чтение потокового тела при явном повторном запросе остаётся ответственностью вызывающего кода |
| HTTP/1.1 | отдельные Host/request-target, отключение default headers; порядок/регистр/повторы в поддерживаемом raw path проверяются loopback-тестами | Не все обычные режимы и proxy формы используют raw path; точность заявлять только для покрытого режима |
| TLS | импорт профиля v1, ручная настройка поддержанных ClientHello-полей, CLI и Go API SNI override и границ версии TLS; Go API также поддерживает выбор TLS 1.0–1.2 cipher suites и экспериментальную гибридную группу X25519MLKEM768 (PostQuantum), фактический захват ClientHello, JA3/JA4/TLS-NORM и сравнение политики | PostQuantum доступен для поддерживаемых TCP TLS соединений с HTTPS-URL; несовместим с ручным `TLSProfile.ClientHello` и HTTP/3; TLSCipherSuites не меняет TLS 1.3 suites; набор materializable uTLS-полей ограничен; неподдержанное MUST должно завершаться UNSUPPORTED, а не считаться совпадением |
| HTTPS-прокси | отдельные profile/check настройки для proxy TLS и target TLS; `--proxy-insecure`/`Request.ProxyInsecure` отдельно отключают проверку сертификата прокси; Go API end-to-end HTTPS CONNECT → target TLS → HTTP/1.1 проверен локальным listener | Фактический ALPN и сочетания TLS engine должны оставаться согласованными с транспортом |
| HTTP/2 | Подмножество SETTINGS, их порядок, порядок pseudo/обычных заголовков, пределы HEADERS/DATA, padding и PRIORITY; wire-поля проверяются loopback-тестами | Нет настройки flow-control окон, произвольного HPACK/frame replay, полного scheduler или гарантированного reuse соединения |
| HTTP/3 | Дополнительный SETTINGS, datagrams, часть QUIC transport parameters и их порядок; ClientHello наблюдается, включая повторный ClientHello после HelloRetryRequest | TLS использует стандартный crypto/tls; uTLS preset не материализуется для QUIC; нет произвольного QUIC packet replay |
| Отчёт/API | `pkg/gocurl`, request-local results, connection reports, JSON и redact заголовков | Контракт совместимости и одинаковость CLI/API для каждого режима должны поддерживаться тестами |
| Профиль | JSON Schema и формат v1 с ожидаемыми полями, политиками и ограничениями | Экспорт выполняет JA3Proxy; неизвестные major-версии и неразрешённые MUST поля отклоняются |

### 3.1 Точные текущие границы HTTP/2

Матрица фактической поддержки HTTP/2 (значения и порядок wire-полей подтверждаются
локальными тестами на loopback-сервере):

| Элемент | Статус | Подтверждение / точная граница |
| --- | --- | --- |
| SETTINGS | Частично поддерживается | Настраиваются `HEADER_TABLE_SIZE`, `MAX_FRAME_SIZE` и `MAX_HEADER_LIST_SIZE`; можно задать порядок передаваемых SETTINGS. `TestHTTP2SettingsOnWire` проверяет значения и порядок. Остальные ID не становятся настраиваемыми только от включения в список порядка: транспорт отправляет лишь применимые значения. |
| Порядок pseudo-headers и обычных заголовков | Поддерживается с ограничениями | `TestHTTP2PseudoHeaderOrderOnWire` проверяет порядок на wire. Заголовки кодируются заново: байты исходного HPACK-блока, dynamic table и её история не сохраняются. |
| HEADERS и CONTINUATION | Частично поддерживается | Настраивается предел размера payload заголовочных кадров; тест проверяет фрагментацию на HEADERS/CONTINUATION. Произвольные границы и порядок всех кадров соединения не задаются. |
| Padding для HEADERS и DATA | Поддерживается в объявленном режиме | Loopback-тесты проверяют padded-флаг и число padding-байтов соответствующих кадров. |
| DATA | Частично поддерживается | Можно ограничить размер payload и задать padding; `TestHTTP2DataFrameSizeOnWire` проверяет размеры кадров, padding и восстановленные байты тела. |
| PRIORITY | Поддерживается для первого request stream | `TestHTTP2PriorityFrameOnWire` проверяет stream ID, зависимость, вес и exclusive. Это не полный scheduler и не управление зависимостями произвольных потоков. |
| Flow-control окна | Не настраиваются | CLI/API не предоставляют полей для начального stream window и connection window. Значения/обновления остаются под контролем HTTP/2-транспорта; произвольный WINDOW_UPDATE replay не поддерживается. |
| Повторное использование соединения | Не гарантируется | Текущая реализация `h2Transport.RoundTrip` создаёт ClientConn для выполняемого запроса; API не обещает pooling/reuse между запросами. Повторный вызов не следует считать тем же TCP/TLS/HTTP/2-сеансом. |
| Остальные кадры, timing и полный fingerprint | Не поддерживаются | Нет произвольного frame scheduler/replay, контроля всех служебных кадров и точного воспроизведения browser wire fingerprint. |

Изменение порядка pseudo/header полей и часть framing требуют перекодирования
HPACK и не сохраняют исходные HPACK-байты. Часть вмешательств ограничена первым
request header block, поддерживаемыми флагами/типами кадров и запретом
CONNECT/trailers. Поэтому произвольный HTTP/2 capture replay не обещается.

### 3.2 Точные текущие границы QUIC

Диапазоны ниже соответствуют валидатору проекта; defaults — vendored
`quic-go v0.61.0`. Нулевое значение CLI отличается от пропуска только там, где
указано «явный 0».

| Параметр | Допустимое значение CLI | Если опция пропущена / эффект |
| --- | --- | --- |
| `--quic-initial-stream-window` | `1..2^62-1` байт; явный `0` запрещён | 512 KiB. Общий receive window для потоков, если не переопределён типоспецифичными опциями. |
| `--quic-initial-max-stream-data-bidi-local`, `...-bidi-remote`, `...-uni` | Каждое: `0..2^62-1`; явный `0` поддержан и передаётся | Каждое наследует общий stream window; если общий тоже не задан — 512 KiB. |
| `--quic-initial-connection-window` | `1..2^62-1` байт; явный `0` запрещён | 786432 байта (1,5 × 512 KiB). Начальное receive window соединения. |
| `--quic-max-idle-timeout-ms` | `1..MaxInt64/ms`; явный `0` запрещён | 30 секунд. Влияет на рекламируемый idle timeout. |
| `--quic-max-incoming-streams` | `1..2^60` | 100 bidirectional streams. Ограничивает число peer-initiated потоков. |
| `--quic-max-incoming-uni-streams` | `3..2^60` | 100 unidirectional streams; минимум 3 оставляет HTTP/3 control и QPACK streams. |
| `--quic-version` | `1` или `2` | Разрешены версии quic-go `[1, 2]`; заданная опция ограничивает выбор одной версией. |
| `--quic-initial-packet-size` | `1200..1452` байта | 1280 байт для исходного Initial datagram. |
| `--quic-connection-id-length` | `1..20` байт | 4 байта для source connection ID клиента. |
| `--quic-active-connection-id-limit` | `2..4` | 4; верхняя граница — лимит хранения connection IDs в используемом quic-go. |
| `--quic-ack-delay-exponent` | `0..20`; явный `0` поддержан | 3. |
| `--quic-max-ack-delay-ms` | `0..16383`; явный `0` поддержан | 26 ms в defaults quic-go (25 ms ACK delay + 1 ms timer granularity). |
| `--quic-max-udp-payload-size` | `1200..1452` байта | 1452 байта; это ограничение данного транспорта, не произвольный path MTU. |
| `--quic-disable-active-migration`, `--quic-reset-stream-at` | Флаги | По умолчанию выключены; первый включает стандартный transport parameter, второй — экспериментальный extension parameter. |
| HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE` (`0x6`) | Не настраивается отдельной опцией | Фиксировано на 10 MiB (`MaxResponseHeaderBytes` default quic-go); значение подтверждает `TestHTTP3AdditionalSettingsOnWire`. |
| HTTP/3 QPACK settings (`0x1`, `0x7`) и Extended CONNECT (`0x8`) | Не настраиваются | Клиент их не отправляет; для QPACK остаются protocol defaults, Extended CONNECT не включается. Wire-тест проверяет отсутствие этих ID. |
| `--h3-datagrams` | Флаг | По умолчанию выключено; включает HTTP/3 `SETTINGS_H3_DATAGRAM=1` и QUIC `max_datagram_frame_size`. |
| `--h3-setting=ID=VALUE` | ID и VALUE: `0..2^62-1`; VALUE `0` поддержан. ID стандартных/reserved настроек и дубликаты запрещены | Только дополнительные (extension) HTTP/3 settings. Пользовательский порядок не задаётся; extension-ID сериализуются по возрастанию для воспроизводимости. |
| `--quic-transport-parameter-order=ID,...` | Уникальные ID `0..2^62-1`, decimal или `0x` hex | Без опции остаётся исходный порядок quic-go с GREASE. Заданные существующие ID перемещаются после GREASE в указанном порядке; незаданные сохраняют взаимный порядок. Несуществующий в данном соединении ID не создаёт новый параметр. |

`TestQUICTransportParametersOnWire` через серверный qlog проверяет переданные
значения транспортных параметров; отдельный wire-тест сериализатора проверяет
порядок, сохранение GREASE и явные нулевые значения. `TestHTTP3AdditionalSettingsOnWire`
проверяет значения, явный ноль и порядок SETTINGS на control stream;
`TestRequestArgsQUICConfigParity` проверяет
CLI/API parity. Эти возможности не означают управление QUIC ClientHello, packet
coalescing, frame scheduling, потерями, congestion control или таймингом.
QUIC ClientHello наблюдается для всех ClientHello на соединении, включая
повторный ClientHello после HelloRetryRequest; каждый захват получает индекс и
может сравниваться с импортированным профилем. Strict-режим проверяет все
наблюдения и прерывает запрос при несовпадении или неполном наблюдении. QUIC TLS
использует стандартный `crypto/tls`, а не materializer uTLS-профиля, поэтому
произвольные браузерные ClientHello через HTTP/3 пока нельзя сконфигурировать.
Go API сериализуется в те же опции, что использует CLI;
`TestRequestArgsQUICConfigParity` проверяет семантическое восстановление
HTTP/3 settings и QUIC transport parameters, включая явно заданные нулевые
ACK-параметры. Defaults и ограничения указаны в таблице выше; порядок QUIC
transport parameters проверяется отдельно от HTTP/3 SETTINGS, для которых
пользовательское управление порядком не реализовано.

## 4. Требования к HTTP-запросам

1. Сохранять метод, URL/query и байты тела без текстовой перекодировки в
   бинарном режиме. Поддерживать URL, файл и stdin в режимах, уже объявленных
   CLI/API.
2. Заголовки хранить упорядоченными парами там, где требуется wire-порядок;
   повторы и регистр сохранять только в режимах, где транспорт это гарантирует.
   Не описывать `http.Header` как средство гарантированного порядка.
3. Host, request-target, proxy CONNECT headers и target headers — разные
   понятия. Proxy credentials не должны утекать в target request.
4. Проверять конфликты Content-Length/Transfer-Encoding, CR/LF и некорректные
   имена до соединения. Ограничения `--no-default-headers` и `--request-target`
   должны совпадать в CLI help, README, API и тестах.
5. Для redirect/retry указывать каждый фактически отправленный запрос отдельно.
   One-shot body нельзя молча повторить; операция должна завершиться понятной
   ошибкой либо запрос должен быть явно не повторён согласно документированной
   политике.
6. HTTP proxy, HTTPS proxy, SOCKS5 и SOCKS5H сохраняют разные правила
   разрешения DNS и аутентификации. Не менять их семантику без теста.

## 5. Требования к TLS-профилям и сравнению

1. Профиль v1 валидируется по JSON Schema и дополнительным семантическим
   ограничениям. Неизвестная major-версия, неизвестное поле, невалидное
   перечисление и неподдержанное MUST-поле дают явную ошибку до dial.
2. Сравнивать фактически отправленный ClientHello, не только объект настроек,
   выбранный preset либо готовую JA3-строку. Проверять порядок и значения тех
   полей, которые входят в контракт профиля.
3. JA3/JA4 и нормализованный hash рассчитываются одной версионированной
   реализацией; GREASE и динамические поля обрабатываются по версии
   нормализации. Совпадение hash не отменяет MUST/SHOULD policy.
4. Сравнение поддерживает MUST, SHOULD, ignored-dynamic и constraints:
   MUST mismatch или неизвестный MUST — не MATCH; SHOULD mismatch — частичный
   результат; динамическое поле исключается только по явному правилу профиля.
5. TLS к proxy и target имеет независимые профили, connection IDs, attempts,
   результаты и strict-политики. Запросы конкурентного API не используют
   глобальный mutable “last connection”.
6. При повторном использовании соединения не создавать фиктивный новый
   ClientHello. Отметить reuse отдельно от нового наблюдения.
7. TLS к HTTP/3 сравнивать только с захваченным QUIC ClientHello; не считать
  выбранный uTLS preset реально применённым к QUIC. Неполный capture и
  mismatch в strict режиме завершают запрос ошибкой.

### 5.1 Статусы

- `MATCH` — все требуемые MUST-поля совпали, capture полный.
- `PARTIAL_MATCH` — MUST выполнены, но есть SHOULD-расхождения или явно
  частично поддержанные необязательные поля.
- `MISMATCH` — нарушено хотя бы одно MUST.
- `UNSUPPORTED` — формат/версия/обязательное поле не поддерживаются.
- `INCOMPLETE` — capture начат, но не содержит достаточно данных.
- `NOT_OBSERVED` — ClientHello не был захвачен (в том числе неподдержанный
  QUIC путь); это не MATCH.
- `REUSED_CONNECTION` — новый handshake не выполнялся из-за reuse.
- `CONNECTION_ERROR` — ошибка TLS/сети до полного capture.
- `OBSERVED` — фактический capture сформирован, но сравнение не запрошено.

`--tls-profile-strict` и `--proxy-tls-profile-strict` подразумевают
соответствующую проверку и требуют точного `MATCH`; любой иной статус, включая
`PARTIAL_MATCH`, `NOT_OBSERVED` и `REUSED_CONNECTION`, должен завершать
операцию ошибкой. JSON status, текст ошибки и exit code должны указывать на
одну причину. Если код расходится с этим правилом, расхождение остаётся
открытым пунктом backlog.

## 6. JSON и публичный Go API

1. Публичный пакет `pkg/gocurl` — поддерживаемый embedding API. Его типы и
   результат документируются отдельно от внутренней CLI-конфигурации.
2. Результат JSON сохраняет обратную совместимость существующих полей и
   добавляет структурированные request/connection reports. Ошибки JSON-режима
   также остаются JSON, включая ошибки разбора аргументов.
3. Request report описывает реально выбранные method, URL, protocol, host,
   target, подготовленные заголовки, content length и transfer encoding.
   `configured_header_order` — это заданный порядок, не обещание полного
   порядка HTTP/2/3.
4. Connection report содержит `connection_id`, `leg`, `attempt`,
   `hello_index`, статус, expected/actual/diff, версии engine и нормализации.
   Сырые handshake bytes и секреты не выдаются по умолчанию.
5. Redaction изменяет только JSON metadata, не отправляемый запрос. При
   редактировании Authorization исключать из metadata и credentials из URL.
6. Добавление полей API не должно менять значение zero/nil существующих полей.
   CLI→API и API→CLI семантика проверяется contract-тестами, в том числе
   explicit zero для параметров, где ноль валиден.

## 7. Ошибки и коды завершения

Закрепить и поддерживать коды:

- `0` — запрос успешен и обязательная политика соблюдена;
- `2` — аргументы, профиль или неподдерживаемая конфигурация;
- `3` — TLS/HTTP/сетевая ошибка;
- `4` — MISMATCH или нарушение MUST;
- `5` — неполное/отсутствующее обязательное наблюдение.

Если текущая реализация или исходный gocurl расходятся с этой таблицей,
обновить код и тесты в рамках соответствующего backlog-пункта; не маскировать
разницу документацией. Прямой и JSON вывод должны сообщать одну и ту же ошибку.

## 8. Результат аудита и единый backlog

Аудит 2026-09-29 разделяет три состояния: **ВЫПОЛНЕНО** — код, отрицательные
границы и требуемое wire/e2e-доказательство присутствуют; **ЧАСТИЧНО** — основной
путь работает, но перечисленные доказательства отсутствуют; **НЕ ВЫПОЛНЕНО** —
результат нельзя воспроизвести из чистого checkout либо обязательного поведения
нет. Наличие флага, имени поля в README или unit-теста преобразования не закрывает
сквозной контракт.

### 8.1 Подтверждённая база

- QUIC ClientHello capture, включая повторный ClientHello после
  HelloRetryRequest, индекс наблюдения и strict mismatch, подтверждён локальными
  HTTP/3 тестами. Статус: **ВЫПОЛНЕНО**.
- HTTP/2 профиль закрыт для подмножества и ограничений раздела 3.1. Произвольный
  HPACK/frame replay и управление окнами не входят в обещанный контракт. Статус:
  **ВЫПОЛНЕНО В ДОКУМЕНТИРОВАННЫХ ГРАНИЦАХ**.
- HTTP/3/QUIC профиль закрыт для параметров раздела 3.2, включая explicit zero,
  qlog/wire evidence и CLI/API parity. uTLS ClientHello для QUIC и произвольный
  packet replay не входят в обещанный контракт. Статус: **ВЫПОЛНЕНО В
  ДОКУМЕНТИРОВАННЫХ ГРАНИЦАХ**.
- Бинарное тело с известной и неизвестной длиной, файл/stdin и отсутствие
  автоматического retry реализованы. Go API возвращает первый 307 и не
  переотправляет one-shot body. Та же политика проверена CLI e2e-тестом
  `TestCLIDataBinaryReturnsFirstRedirectWithoutRetry`. Статус:
  **ВЫПОЛНЕНО В ДОКУМЕНТИРОВАННЫХ ГРАНИЦАХ** (см. пункт 4 ниже).

### 8.2 Порядок оставшихся работ

1. **P0 — сделать дерево репозитория воспроизводимым. Статус: ВЫПОЛНЕНО.**
   9 октября исходники, `pkg/`, schema, protocol/wire tests и `vendor/`
   зафиксированы в собственном `main` goCURL коммитом `9342027`.
   Отслеживается 2090 файлов; untracked source files отсутствуют. Кэши,
   бинарники, ключи, captures и локальные базы исключены ignore; среди
   2077 staged paths таких файлов не было. Перед коммитом выполнен
   GitNexus staged impact analysis; накопленный scope оценён CRITICAL и
   явно разрешён пользователем.
   Из независимого чистого local clone этого коммита на Windows amd64
   прошёл весь `scripts/check.ps1`: mod verify, форматирование/lint,
   markdownlint, vet, race suite с benchmarks, vendored QUIC wire tests и
   all-package build. После gate нет tracked/untracked изменений.
   Состав QUIC-патча описан в `docs/VENDORED_QUIC_PATCH.md`.
   Это доказательство воспроизводимости зафиксированных исходников,
   не fresh remote CI или проверки всех ОС; они остаются в пункте 7.
   Полный путь проверенного checkout и границы — в
   [отчёте](FUZZ_REPORT_2026-10-09.md).

2. **P0 — завершить сквозную матрицу capture status/exit code. Статус:
   ВЫПОЛНЕНО.** Таблица кодов и JSON serialization покрыты unit-тестами;
   перечисленные ниже состояния проверяются на реальных локальных сценариях
   там, где статус возникает при сетевом обмене, и на уровне Go API/CLI JSON.

   | Статус | Фактическое покрытие | Что требуется для закрытия |
   | --- | --- | --- |
   | `MATCH` / `OBSERVED` | TLS/QUIC loopback и API reports; `TestCLISuccessJSONIncludesObservedTLSFingerprint` проверяет успешный CLI JSON с JA3/JA4 и `OBSERVED` | Сохранить как регрессионную базу |
   | `PARTIAL_MATCH` | Unit, Go API и реальный CLI subprocess | Закрыто тестом `TestCLIStrictPartialMatchJSONAndExitCode`: JSON, stderr, code 4 и отсутствие HTTP request после strict-отказа |
   | `MISMATCH` | API direct, HTTP/HTTPS CONNECT, HTTP/2 и SOCKS; `TestCLIStrictMismatchJSONAndExitCode` проверяет реальный TLS mismatch, JSON, stderr, code 4 и отказ до HTTP handler; `TestResponseJSONUsesSameConnectionReportShapeAcrossTLSLegs` сравнивает поля `proxy`, `target` и `gateway` | Сохранить одинаковую JSON-схему при добавлении новых TLS legs |
   | `UNSUPPORTED` | Decoder/config, CLI JSON и типизированная ошибка Go API до dial | Закрыто тестами `TestCLIUnsupportedProfileJSONExitCodeBeforeDial` и `TestClientDoRejectsUnsupportedTLSProfileBeforeNetwork` |
   | `INCOMPLETE` | Parser/capture, Go API и реальный CLI subprocess | Закрыто тестами `TestClientDoReportsIncompleteWhenClientHelloWriteIsInterrupted` и `TestCLIIncompleteClientHelloJSONAndExitCode`: listener принимает только первые 5 байт ClientHello и разрывает TCP; API сохраняет типизированный статус, CLI возвращает JSON и code 5 |
   | `NOT_OBSERVED` | ECH/PQ и strict tests; `TestClientDoECHGreaseReportsUnobservedHandshake` проверяет Go API, `TestCLIECHGreaseJSONReportsNotObserved` — CLI subprocess, JSON report и успешный exit code | Сохранить регрессионную базу |
   | `REUSED_CONNECTION` | OHTTP same-origin HTTP/1.1: один TLS connection для keys и gateway; проверены CLI JSON, публичный Go API, отчёт gateway и strict code 5 | Сохранить как регрессионную базу; дополнить межпротокольными сценариями при изменении пула соединений |
   | `CONNECTION_ERROR` | Реальный TLS failure после TCP connect через CLI и Go API | Закрыто тестами `TestCLIConnectionErrorJSONExitCodeAfterDial` и `TestClientDoReportsConnectionErrorAfterTLSHandshakeStarts`; CLI проверяет code 3 и JSON shape |

3. **P1 — закрыть минимальную contract matrix маршрутов. Статус: ВЫПОЛНЕНО.**
   Уже доказаны direct HTTP/1.1, HTTP/2 и HTTP/3; HTTP/HTTPS CONNECT к TCP
   target; SOCKS5/SOCKS5H для HTTP/1.1, HTTP/2 и UDP HTTP/3; ECH/PQ через
   основные TCP proxy; CLI WSS по direct/HTTP/HTTPS/SOCKS; OHTTP transport по
   HTTP/HTTPS/SOCKS. Go API и совместимость дополнительно закрыты следующими
   регрессионными проверками:

   - Go API `wss://` direct и через HTTP, HTTPS, SOCKS5 и SOCKS5H с TLS к target,
     проверкой SNI/Host, `Sec-WebSocket-Accept` и обменом masked frame — закрыто
     `TestClientDoWSSAcrossDirectAndProxyRoutes` для всех пяти маршрутов;
   - Go API OHTTP через HTTP, HTTPS, SOCKS5 и SOCKS5H — покрыто
     `TestClientDoOHTTPThroughHTTPAndSOCKSProxies`, включая CONNECT/ATYP,
     расшифрованный target URL и фактический reuse одного соединения;
   - публичный Go API PQ и принятый ECH через direct, HTTP, HTTPS, SOCKS5 и
     SOCKS5H закрыты `TestClientDoPostQuantumHandshakeAcrossProxyRoutes` и
     `TestClientDoECHAcceptedAcrossProxyRoutes`: проверяются фактическое
     X25519MLKEM768 согласование, принятие ECH локальным сервером, Host/path и
     SOCKS ATYP;
   - таблица совместимости ниже; API-тесты подтверждают отказ до сети для
     HTTP/3+HTTP(S) proxy, WebSocket+HTTP/2/3 и manual TCP profile+HTTP/3;
   - документированная политика reuse по каждому протоколу: обычный HTTP/1.1
     создаёт новое TLS-соединение (проверяет
     `TestClientDoHTTP11CreatesNewTLSConnectionPerCall`); OHTTP переиспользует
     HTTP/1.1 connection для keys и gateway только при совпадающих
     scheme/host/effective port; HTTP/2 reuse не обещается, HTTP/3 reuse
     отчётируется.

   Совместимость протоколов и транспортов:

   | Возможность | Поддерживается | Не поддерживается / отказ до сети |
   | --- | --- | --- |
   | HTTP/3 | Direct, SOCKS5 и SOCKS5H | HTTP- и HTTPS-proxy; `TestClientDoRejectsHTTP3HTTPProxyBeforeNetwork` проверяет отсутствие подключения к proxy |
   | WebSocket (`ws://`, `wss://`) | HTTP/1.1 direct и через поддерживаемые proxy | HTTP/2 и HTTP/3; API-тест `TestClientDoRejectsWebSocketHTTPVersionsBeforeNetwork` проверяет 4 сочетания и отсутствие подключения |
   | Ручной TCP TLS ClientHello profile | HTTPS поверх HTTP/1.1 или HTTP/2 при совместимом ALPN | HTTP/3/QUIC; `TestClientDoRejectsTLSProfileWithHTTP3BeforeNetwork` проверяет отсутствие QUIC-пакетов |
   | Post-quantum TLS | HTTPS поверх поддерживаемого TCP-транспорта, включая HTTP(S)- и SOCKS-proxy | HTTP/3/QUIC и совместное использование с ручным ClientHello profile |

4. **P1 — завершить body/redirect/retry contract. Статус: ВЫПОЛНЕНО.**
   `TestCLIDataBinaryReturnsFirstRedirectWithoutRetry` теперь проверяет CLI e2e
   для one-shot stdin/file body: один фактически отправленный запрос,
   неизменные бинарные байты, streaming/known content length и возврат первого
   307 без redirect/retry. `TestClientDoStreamingBodyFailureDoesNotRetry`
   отдельно проверяет отмену контекста и ошибку чтения streaming body через
   публичный Go API, быстрое распространение ошибки и ровно одну сетевую
   попытку.

5. **P1 — сделать API/CLI parity исчерпывающей. Статус: ЧАСТИЧНО.**
   README теперь содержит контрактную таблицу для всех 43 полей `Request` с
   CLI mapping, zero/nil semantics, основными ограничениями и регрессионными
   тестами. `TestRequestFieldContractTableCoversEveryField` сверяет таблицу с
   Go struct и проверяет, что упомянутые тесты существуют;
    `TestReadmeLongOptionSetMatchesCLIOptions` сверяет полный набор long-флагов
    help-блока с `config.Options`, а `TestReadmeLongOptionDescriptionsMatchCLIOptions`
    требует полного совпадения описания каждого флага с соответствующим
    `description`-тегом CLI. В help-блоке также восстановлены пропущенные
   `--json-redact-header`, `--quic-connection-id-length`,
   `--quic-reset-stream-at` и `--quic-transport-parameter-order`. Публичный
   `Client.Do` дополнительно проверяет на локальном TLS listener фактические
   значения и порядок HTTP/2 SETTINGS из `Request.HTTP2Settings` и
   `Request.HTTP2SettingsOrder` (`TestClientDoHTTP2SettingsAndOrderOnWire`), а
   также размер DATA payload, фрагментацию и padding HEADERS/CONTINUATION,
   порядок pseudo/regular headers и PRIORITY из API-запроса
   (`TestClientDoHTTP2FrameControlsOnWire`). Публичный Go API также проверяет
   SETTINGS HTTP/3, включая extension ID/value, explicit zero, порядок и
   datagram negotiation (`TestClientDoHTTP3SettingsOnWire`).
   QUIC transport values, initial packet size, source connection ID length и
   выбранную версию дополнительно проверяет API-level qlog/listener-тест
   (`TestClientDoQUICTransportParametersOnWire`), а API-level тест
   расшифровывает QUIC v2 Initial и проверяет сырой порядок параметров в
   ClientHello (`TestClientDoQUICTransportParameterOrderOnWire`). Для TLS
   публичный API теперь проверяет
   фактически согласованный TLS 1.2 cipher suite на локальном сервере и точное
   32-байтовое значение ClientHello random на wire
   (`TestClientDoTLSCipherSuitesOnWire`, `TestClientDoTLSRandomOnWire`), а
   также действительное разделение ClientHello с задержкой и успешное
   продолжение TLS/HTTP handshake через локальный listener
   (`TestClientDoTLSSplitHelloOnWire`). Custom DNS upstream и IPv4-only уже
   покрыты API-тестом; добавлен аналогичный IPv6-only сценарий с локальным
   DNS/HTTP, который автоматически пропускается только если ОС запрещает
   исходящие IPv6 loopback-соединения (`TestClientDoUsesCustomDNSUpstreamAndIPv6Only`).
   `ConnectTimeout` также проверяется через публичный API на фактическом
   HTTPS-proxy TLS handshake, который зависает до истечения заданной секунды
   (`TestClientDoConnectTimeoutBoundsHTTPSProxyTLSHandshake`).
   Ручной `TLSProfile.ClientHello` проверяется успешным публичным API
   handshake: сервер подтверждает заданные SNI, ALPN, TLS 1.2 и cipher suite
   (`TestClientDoManualTLSClientHelloFieldsOnWire`); отдельный wire-тест
   проверяет `SupportedGroups`, `SignatureAlgorithms` и фактическую перестановку
   extension order (`TestClientDoManualTLSClientHelloExtensionFieldsOnWire`).
   Пункт остаётся частичным: аналогичные API-level wire/e2e доказательства
   требуются для остальных wire-значимых полей, а также отрицательные границы
   там, где они применимы.

6. **P1 — убрать публичную сеть из обязательных тестов. Статус: ВЫПОЛНЕНО.**
   CLI OHTTP-сценарии используют локальные key-config/gateway endpoints и
   проверяют расшифрованный target URL как напрямую, так и через локальный
   CONNECT proxy. Resolver-тесты направлены на локальный UDP DNS server.
   Cloudflare ECH/PQ smoke-тесты сохранены как opt-in и запускаются только при
   `GOCURL_NETWORK_INTEGRATION=1`; по умолчанию они пропускаются. Обязательный
   suite не обращается к публичным DNS или HTTP endpoints.

7. **P1 — синхронизировать CI и заявленный quality gate. Статус: ЧАСТИЧНО.**
   `make check` и GitHub Actions используют vendored зависимости и включают
   `go mod verify`, race suite, `go vet`, all-package build, markdownlint,
   `golangci-lint` и отдельные vendored QUIC wire tests. Все schema/golden
   проверки входят в `go test ./...`; CI после выполнения gate проверяет чистый
   checkout, включая untracked generated-файлы. До закрытия необходимо устранить
   либо узко и обоснованно классифицировать текущие замечания
   `golangci-lint v2.10.1`; полный локальный запуск обнаружил накопленный долг в
   complexity/duplication, errcheck, staticcheck, revive и gosec.
   Повторный запуск 5 октября 2026 года после исправлений: 699 успешных тестов
   и подтестов с race detector, 3 ожидаемых пропуска; vet, build, mod verify
   и vendored QUIC wire tests проходят. Полный lint без лимитов вывода
   проходит с 0 замечаний; последние 52 диагностики gocyclo устранены без
   изменения порога сложности и отключения test lint.
   TLS/QUIC dial, HTTP/SOCKS negotiation, ручной профиль Client.Do и wire-тесты
   разделены на специализированные helpers. Сохранены совместимость
   параметров, strict-приоритет, callbacks, golden-отпечатки, partial-result
   state и проверки всех протокольных маршрутов.
   Исправлена потеря первых байтов HTTP/HTTPS CONNECT-туннеля; сохранены
   proxy TLS observations. Устранена Windows bind-нестабильность DNS UDP→TCP
   fixture, подтверждённая стресс-проверкой; 5000 повторов fallback прошли.
   Подробности и незакрытые ограничения — в
   [отчёте исправлений](FIX_REPORT_2026-10-04.md).
   9 октября полный штатный gate дополнительно прошёл из независимого
   чистого checkout коммита `9342027`, без изменений source tree после него.
   Пункт остаётся ЧАСТИЧНО до свежего remote CI, включая Linux/macOS jobs;
   push и релизный тег в этом шаге не выполнялись.

8. **P2 — расширить отрицательные и fuzz-тесты parser-слоя. Статус: ЧАСТИЧНО.**
   Fuzzing покрывает TLS ClientHello capture/fingerprint и header-file parser
   (валидные/пустые данные, битый UTF-8, CR/LF и синтаксические границы).
   Добавлен QUIC v2 Initial capture parser fuzz: воспроизведён и исправлен
   panic при payload короче packet number; 10-секундный прогон обработал
   424885 входов без сбоев. Это проверка test helper, не всего QUIC-стека.
   5 октября добавлен `FuzzNormalizedExtensionFields` со всеми семействами
   TLS-NORM-1 dispatcher: 366007 входов за 10 секунд без сбоев; malformed,
   concrete-type и JSON golden-регрессии проходят. Короткий прогон не доказывает
   отсутствие любых ошибок или совместимость с произвольным capture.
   9 октября добавлены семь fuzz-targets для profile JSON/constraints,
   HTTP/2 settings/order, QUIC numeric transport options/parameter order и
   SOCKS UDP address parsing. Короткие прогоны по 20 секунд с двумя workers
   обработали суммарно 2187407 входов; найдено и исправлено принятие портов
   вне 0..65535 в SOCKS UDP address helper. Нулевой порт остаётся допустимым.
   Форматирование/lint, полный race suite с benchmarks, vet, build, mod verify
   и vendored QUIC wire tests прошли. Подробности и воспроизведение — в
   [отчёте fuzz-проверки](FUZZ_REPORT_2026-10-09.md).
   Пункт остаётся ЧАСТИЧНО: требуются длительные fuzz-прогоны, аудит непокрытых
   критичных ветвей parser/connection report/proxy error paths. Чистый checkout
   подтверждён пунктом 1. Последний ранее измеренный общий statement coverage —
   72,7%; это историческое значение, не новый замер и не критерий само по себе.

9. **P2 — устранить противоречия документации. Статус: ЧАСТИЧНО.**
   `AGENTS.md` теперь корректно указывает `pkg/gocurl` как публичный API, а
   README ссылается на отдельное описание vendored QUIC-патча. Ещё нужны
   безопасные локальные примеры для основных режимов и примеры каждого
   семейства `Request` fields; точные ограничения WebSocket message API и
   HTTP/2/QUIC replay уже зафиксированы. Обновлять README, help, schema,
   CHANGELOG и это ТЗ одним логическим изменением.
   9 октября исправлены дублирование body framing инструкции, перепутанные
   подписи `max_ack_delay`/`max_udp_payload_size`, описание QUIC parameter order
   и последнего полного ClientHello после HRR. AGENTS больше не утверждает,
   что обязательные resolver/OHTTP tests требуют публичной сети или что CLI
   tests никогда не запускают бинарник. Wire-контракт, флаги и schema в этом
   изменении не расширялись.

10. **P3 — косметика и сопровождаемость. Статус: НЕ ВЫПОЛНЕНО.** После закрытия
    P0/P1 сократить дублирующие helpers тестовых proxy/listener, разбить крупные
    test files по областям и устранить устаревшие TODO. Рефакторинг не должен
    менять wire behavior и выполняется только с impact analysis и полным suite.

## 9. Критерии приёмки

Пункт backlog закрывается только если:

1. изменены реализация и документация с точным описанием ограничений;
2. есть unit-тесты парсинга, границ и отрицательных случаев;
3. wire/capture-тест проверяет поведение на локальном listener там, где
   требование относится к отправленным байтам или transport parameters;
4. тест проверяет ошибки/strict/JSON/API для нового поведения;
5. из чистого checkout проходят `go mod verify`, форматирование,
   `go test -count=1 -mod=vendor ./...`, `go test -race -mod=vendor ./...`,
   `go vet -mod=vendor ./...`, `go build -mod=vendor ./...`, linters и
   vendored QUIC wire tests;
6. обязательный suite проходит без публичных DNS/сайтов; тесты не используют
   реальные captures без законного источника;
7. все необходимые новые и vendored файлы отслеживаются Git, а кэши, ключи,
   локальные базы, captures и бинарники отсутствуют в изменениях;
8. неподдержанное MUST или несовместимая комбинация не выдаются за успешное
   совпадение;
9. статус в этом ТЗ обновлён по доказательствам, а не по наличию реализации.

## 10. Принципы дальнейшей работы

- Сохранять совместимость обычных сценариев gocurl и текущих значений по
  умолчанию.
- Работать в `main`; отдельные ветки не создавать.
- Не вводить внешние сервисы или хранилища для локального клиента.
- Не расширять scope до изменений JA3Proxy, если для контракта достаточно
  совместимых изменений gocurl.
- Не закрывать backlog по факту наличия флага: требуются wire evidence и тест.
- Не писать «всё готово», пока P0/P1 имеют открытый статус.

## Приложение A. Фактическая проверка текущего дерева

На 2026-09-29 в текущем рабочем дереве успешно выполнены:

- `go test -count=1 -timeout=2m -mod=vendor ./...`;
- `go test -race -count=1 -timeout=3m -mod=vendor ./...`;
- `go vet -mod=vendor ./...`;
- `go build -mod=vendor ./...`;
- `git diff --check` (без whitespace errors; присутствуют только предупреждения
  Git о преобразовании LF/CRLF).

Повторный полный `go test` и race suite также прошли с `HTTP_PROXY`,
`HTTPS_PROXY` и `ALL_PROXY`, направленными на недоступный локальный порт, и без
`GOCURL_NETWORK_INTEGRATION`. Это подтверждает отсутствие обязательной
зависимости от публичных HTTP endpoints; локальные loopback-сервисы разрешены.

Coverage-прогон показал 72,7% statements по всему модулю. Это диагностическая
метрика, а не критерий готовности отдельных протокольных контрактов.

Markdownlint для всего дерева успешно выполнен через
`npx --yes markdownlint-cli`. Установленный `golangci-lint v2.10.1`, собранный
тем же Go 1.26.6, выявляет накопленный долг в complexity/duplication, errcheck,
staticcheck, revive и gosec, поэтому полный `make check` пока не является
зелёным. Кроме того, рабочее дерево содержит большое количество modified и
untracked файлов, включая `pkg/` и `vendor/`; поэтому успешные тесты текущего
дерева ещё не доказывают воспроизводимость из чистого clone. Эти ограничения
отражены в пунктах 1, 6 и 7 backlog.
