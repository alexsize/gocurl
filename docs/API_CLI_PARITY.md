# Матрица API/CLI parity goCURL

Дата проверки: 11 октября 2026 года. Область: публичный API v1,
`pkg/gocurl`, документированное подмножество HTTP/1.1, HTTP/2 и HTTP/3.

## Правила доказательства

- CLI mapping всех 43 полей `Request` и zero/nil semantics находятся в
  [README](../README.md#request-field-contract). Ниже отдельно учтены и поля
  вложенных публичных типов. `TestAPIParityMatrixCoversPublicRequestTypes`
  сверяет состав с Go reflection, запрещает пропуски/дубликаты и проверяет
  существование указанных wire/e2e-тестов. Сам по себе этот тест не доказывает
  корректность транспорта: для каждой строки нужен запуск соответствующего теста.
- `TestRequestFamiliesMatchIndependentCLIConfig` сравнивает весь validated
  `config.Config` для API и независимо написанных CLI arguments в 14 сценариях.
  Исключены только `RawOptions` (logging) и объекты DNS upstream: для них отдельно
  сравниваются адреса, затем оба набора закрываются. Проверяются defaults,
  HTTP/1.1 metadata, TLS, routing, IPv6, proxy policies, HTTP/2, HTTP/3/QUIC,
  ECH/GREASE/PQ, OHTTP и независимые target/proxy check/strict.
- **B** в последнем столбце означает 99 сценариев
  `TestClientDoRejectsInvalidRequestBoundariesBeforeNetwork`: вызов публичного
  `Client.Do`, проверка ошибки, nil Result, непрочитанного тела и отсутствия TCP
  соединений/UDP пакетов на локальных listeners. Проверяются диапазоны,
  ошибочные имена/форматы и несовместимые комбинации, представимые типами Go.
- **Тип Go** означает, что значение вне диапазона типа нельзя передать API.
  Нулевые значения unsigned scalar — defaults, а не ошибка и не explicit zero.
  Пять pointer-настроек QUIC сохраняют отличие nil от явного нуля.
- **Булево** означает отсутствие собственного некорректного числового значения;
  применимость определяется протоколом/маршрутом. `Insecure` и `ProxyInsecure`
  дополнительно проверяются всеми четырьмя сочетаниями true/false для default
  TLS и imported uTLS, включая количество CONNECT и target HTTP requests.
- Тело — `io.Reader`, не CLI-строка; CLI file/stdin и API reader не обязаны иметь
  одинаковую реализацию источника. Проверяются реальные байты, framing, длина,
  отсутствие retry и redirect replay. Ручной `TLSClientHello` — API-only;
  CLI использует импортированный JSON profile, а не отдельные флаги его полей.

## Все поля Request

| Поле | CLI / особенность API | Wire/e2e-доказательство | Отрицательная граница |
| --- | --- | --- | --- |
| `Request.URL` | Positional URL | `TestClientDoOHTTPUsesGatewayAndPreservesRequest` | B; `TestClientDoRejectsMissingURLBeforeNetwork` |
| `Request.Method` | `--request` | `TestClientDoPreservesKnownAndUnknownBinaryBodyLengths` | Некорректный метод отклоняет HTTP request builder; B |
| `Request.TLSServerName` | `--tls-servername`; Host не меняется | `TestClientDoOverridesTLSServerNameWithoutChangingHTTPHost` | B: конфликт с manual SNI |
| `Request.TLSMinVersion` | `--tlsv1.2`, `--tlsv1.3` | `TestClientDoEnforcesTLSVersionBounds` | B: значение и min больше max |
| `Request.TLSMaxVersion` | `--tls-max` | `TestClientDoEnforcesTLSVersionBounds` | B: значение и min больше max |
| `Request.TLSCipherSuites` | `--ciphers`; native crypto/tls выбирает порядок | `TestClientDoNativeCipherVectorOnWire` | B: пустое/неизвестное имя, whitespace |
| `Request.PostQuantum` | `--experiment=pq` | `TestClientDoPostQuantumHandshakeAcrossProxyRoutes` | B: HTTP/3; `TestClientDoRejectsPostQuantumImportedProfileBeforeNetwork` |
| `Request.RequestTarget` | `--request-target` | `TestClientDoRequestTargetOverridesWireTargetOnly` | B: форма, CR/LF, HTTP/2 |
| `Request.NoDefaultHeaders` | `--no-default-headers` | `TestClientDoNoDefaultHeadersKeepsOnlyExplicitHeaders` | B: требует HTTP/1.1 |
| `Request.JSONRedactHeaders` | `--json-redact-header`; только metadata | `TestResultRequestMetadataRedactsDetachedHeaderSnapshot` | B: invalid field name |
| `Request.Headers` | Повторяемый `--header` | `TestClientDoPreservesOrderedRepeatedHeadersOnHTTP11Wire` | B: имя, CR/LF, пустой Host |
| `Request.Body` | Reader; CLI file/stdin отдельно | `TestClientDoStreamingBodyFailureDoesNotRetry`; `TestClientDoBodyLengthZeroNegativeAndNilSemanticsOnWire` | Ошибка reader и неверная declared length в этом же тесте |
| `Request.ContentLength` | API-only; CLI выводит из источника | `TestClientDoBodyLengthZeroNegativeAndNilSemanticsOnWire`; `TestClientDoPreservesKnownAndUnknownBinaryBodyLengths` | `TestClientDoStreamingBodyFailureDoesNotRetry`; ноль/отрицательное означают unknown |
| `Request.ProxyURL` | `--proxy` | `TestClientDoWSSAcrossDirectAndProxyRoutes` | B: URL; `TestClientDoRejectsHTTP3HTTPProxyBeforeNetwork` |
| `Request.ProxyInsecure` | `--proxy-insecure` | `TestClientDoTargetAndProxyCertificatePoliciesAreIndependent` | B: нет HTTPS proxy; булево |
| `Request.ConnectTimeout` | `--connect-timeout`; whole seconds | `TestClientDoConnectTimeoutBoundsHTTPSProxyTLSHandshake` | B: отрицательное, fractional |
| `Request.ConnectTo` | `--connect-to` | `TestClientDoConnectToRedirectsSocketWithoutChangingHostOrSNI` | B: формат |
| `Request.Resolve` | `--resolve`; wildcard и IP list | `TestClientDoResolvePinsHostnameToLocalTLSServer`; `TestClientDoWildcardResolvePreservesHostAndSNI` | B: host, IP list, invalid IP |
| `Request.IPVersion` | `--ipv4`, `--ipv6` | `TestClientDoUsesCustomDNSUpstreamAndIPv4Only`; `TestClientDoUsesCustomDNSUpstreamAndIPv6Only` | B: только 4/6; IPv6 skip только при запрете ОС |
| `Request.DNSServers` | `--dns-servers` | `TestClientDoUsesCustomDNSUpstreamAndIPv4Only` | B: empty/whitespace entry |
| `Request.ProxyHTTP2Connect` | `--proxy-http2-connect` | `TestClientDoHTTP2ThroughHTTPSProxyConnect` | B: нет HTTPS proxy; булево |
| `Request.HTTPVersion` | `--http1.1`, `--http2`, `--http3` | `TestClientDoHTTP2AgainstLocalTLSServer`; `TestClientDoHTTP3AgainstLocalQUICServer` | B; `TestClientDoRejectsWebSocketHTTPVersionsBeforeNetwork` |
| `Request.HTTP2Settings` | Подмножество `--h2-*` SETTINGS | `TestClientDoHTTP2SettingsAndOrderOnWire` | B: диапазон MaxFrameSize, требует HTTP/2 |
| `Request.HTTP2PseudoOrder` | `--h2-pseudo-order` | `TestClientDoHTTP2FrameControlsOnWire` | B: duplicate/missing field |
| `Request.HTTP2SettingsOrder` | `--h2-settings-order` | `TestClientDoHTTP2SettingsAndOrderOnWire` | B: неизвестный/повторный ID |
| `Request.HTTP2DataFrameSize` | `--h2-data-frame-size` | `TestClientDoHTTP2FrameControlsOnWire` | B: больше 16384; ноль default |
| `Request.HTTP2HeaderFrameSize` | `--h2-header-frame-size` | `TestClientDoHTTP2FrameControlsOnWire` | B: больше 16384, padding overhead |
| `Request.HTTP2FramePadding` | `--h2-frame-padding` | `TestClientDoHTTP2FrameControlsOnWire` | Тип Go uint8; B: overhead |
| `Request.HTTP2HeaderOrder` | `--h2-header-order` | `TestClientDoHTTP2FrameControlsOnWire` | B: invalid/duplicate name |
| `Request.HTTP2Priority` | `--h2-priority` | `TestClientDoHTTP2FrameControlsOnWire` | B: weight, dependency |
| `Request.HTTP3AdditionalSettings` | `--h3-setting` | `TestClientDoHTTP3SettingsOnWire` | B: reserved ID, uint62 ID/value overflow |
| `Request.HTTP3Datagrams` | `--h3-datagrams` | `TestClientDoHTTP3SettingsOnWire` | B: требует HTTP/3; булево |
| `Request.QUICTransport` | `--quic-*`; вложенные поля ниже | `TestClientDoQUICTransportParametersOnWire`; `TestClientDoQUICSharedAndExplicitZeroWindowsOnWire` | B: все настраиваемые числовые диапазоны |
| `Request.QUICTransportParameterOrder` | `--quic-transport-parameter-order` | `TestClientDoQUICTransportParameterOrderOnWire` | B: duplicate, uint62 overflow |
| `Request.Insecure` | `--insecure` | `TestClientDoTargetAndProxyCertificatePoliciesAreIndependent` | Булево; target и proxy policy независимы |
| `Request.ECH` | `--ech`; DNS discovery без ECHConfig | `TestClientDoDiscoversAndAcceptsECHFromLocalDNS` | Булево; профильные конфликты проверяет Config |
| `Request.ECHGrease` | `--echgrease`; не принятие ECH | `TestClientDoECHGreaseReportsUnobservedHandshake` | Булево; несовместим с imported target profile |
| `Request.ECHConfig` | `--echconfig`; implicit ECH | `TestClientDoECHAcceptedAcrossProxyRoutes` | B: invalid base64 |
| `Request.OHTTPGatewayURL` | `--ohttp-gateway-url` | `TestClientDoOHTTPThroughHTTPAndSOCKSProxies` | B: только в паре с keys URL |
| `Request.OHTTPKeysURL` | `--ohttp-keys-url` | `TestClientDoOHTTPThroughHTTPAndSOCKSProxies` | B: только в паре с gateway URL |
| `Request.TLSRandom` | `--tls-random` | `TestClientDoTLSRandomOnWire` | B: 31/33 вместо 32 bytes |
| `Request.TLSSplitHello` | `--tls-split-hello` | `TestClientDoTLSSplitHelloOnWire` | B: chunk size, negative/fractional delay |
| `Request.TLSProfile` | Import/check/strict; manual API-only | `TestClientDoNonStrictProfileChecksAreIndependent`; `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | B; `TestClientDoRejectsUnsupportedTLSProfileBeforeNetwork` |

## Вложенные публичные поля

| Поле | CLI / особенность API | Wire/e2e-доказательство | Отрицательная граница |
| --- | --- | --- | --- |
| `Header.Name` | Имя в `--header` | `TestClientDoPreservesOrderedRepeatedHeadersOnHTTP11Wire` | B: invalid name |
| `Header.Value` | Значение в `--header` | `TestClientDoPreservesOrderedRepeatedHeadersOnHTTP11Wire` | B: CR/LF |
| `HTTP2Settings.HeaderTableSize` | `--h2-header-table-size` | `TestClientDoHTTP2SettingsAndOrderOnWire` | Тип Go uint32; ноль default; B: вне HTTP/2 |
| `HTTP2Settings.MaxFrameSize` | `--h2-max-frame-size` | `TestClientDoHTTP2SettingsAndOrderOnWire` | B: 16383/16777216 |
| `HTTP2Settings.MaxHeaderListSize` | `--h2-max-header-list-size` | `TestClientDoHTTP2SettingsAndOrderOnWire` | Тип Go uint32; ноль default |
| `HTTP2Priority.Dependency` | Первый stream; `--h2-priority` | `TestClientDoHTTP2FrameControlsOnWire` | B: self=1, больше uint31 |
| `HTTP2Priority.Weight` | 1..256 | `TestClientDoHTTP2FrameControlsOnWire` | B: 0/257 |
| `HTTP2Priority.Exclusive` | PRIORITY exclusive bit | `TestClientDoHTTP2FrameControlsOnWire` | Булево |
| `QUICTransport.InitialStreamReceiveWindow` | Shared receive window | `TestClientDoQUICSharedAndExplicitZeroWindowsOnWire` | B: uint62 overflow; ноль default |
| `QUICTransport.InitialMaxStreamDataBidiLocal` | Pointer; nil/zero distinct | `TestClientDoQUICSharedAndExplicitZeroWindowsOnWire`; `TestClientDoQUICTransportParametersOnWire` | B: uint62 overflow |
| `QUICTransport.InitialMaxStreamDataBidiRemote` | Pointer; nil/zero distinct | `TestClientDoQUICSharedAndExplicitZeroWindowsOnWire`; `TestClientDoQUICTransportParametersOnWire` | B: uint62 overflow |
| `QUICTransport.InitialMaxStreamDataUni` | Pointer; nil/zero distinct | `TestClientDoQUICSharedAndExplicitZeroWindowsOnWire`; `TestClientDoQUICTransportParametersOnWire` | B: uint62 overflow |
| `QUICTransport.InitialConnectionReceiveWindow` | Connection receive window | `TestClientDoQUICTransportParametersOnWire` | B: uint62 overflow |
| `QUICTransport.MaxIdleTimeout` | Whole milliseconds | `TestClientDoQUICTransportParametersOnWire` | B: negative/fractional |
| `QUICTransport.MaxIncomingStreams` | 1..2^60; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: negative/overflow |
| `QUICTransport.MaxIncomingUniStreams` | 3..2^60; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: 2/overflow |
| `QUICTransport.Version` | Версия 1/2, не HTTP version | `TestClientDoQUICTransportParametersOnWire` | B: версия 3 |
| `QUICTransport.InitialPacketSize` | 1200..1452; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: 1199/1453 |
| `QUICTransport.ConnectionIDLength` | 1..20; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: -1/21 |
| `QUICTransport.ActiveConnectionIDLimit` | 2..4; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: 1/5 |
| `QUICTransport.AckDelayExponent` | Pointer; explicit zero | `TestClientDoQUICTransportParametersOnWire` | B: 21 |
| `QUICTransport.MaxAckDelay` | Pointer; whole milliseconds, explicit zero | `TestClientDoQUICTransportParametersOnWire` | B: negative/fractional/16384 ms |
| `QUICTransport.MaxUDPPayloadSize` | 1200..1452; ноль default | `TestClientDoQUICTransportParametersOnWire` | B: 1199/1453 |
| `QUICTransport.EnableResetStreamAt` | `--quic-reset-stream-at` | `TestClientDoQUICTransportParametersOnWire` | Булево; только HTTP/3 |
| `QUICTransport.DisableActiveMigration` | `--quic-disable-active-migration` | `TestClientDoQUICTransportParametersOnWire` | Булево; только HTTP/3 |
| `TLSSplitHello.FirstChunkSize` | Положительный chunk size | `TestClientDoTLSSplitHelloOnWire` | B: 0 |
| `TLSSplitHello.Delay` | Whole milliseconds, включая 0 | `TestClientDoTLSSplitHelloOnWire` | B: negative/fractional |
| `TLSProfile.ProfilePath` | `--tls-profile` | `TestClientDoHTTP11ThroughHTTPSProxyConnect` | B: HTTP/3; unsupported MUST |
| `TLSProfile.Check` | `--tls-profile-check` | `TestClientDoNonStrictProfileChecksAreIndependent` | B: без imported expectations |
| `TLSProfile.Strict` | `--tls-profile-strict` implies Check | `TestClientDoStrictTargetTLSProfileMismatchStopsHTTPSProxyConnectRequest` | B: без profile; strict mismatch до HTTP |
| `TLSProfile.ProxyProfilePath` | `--proxy-tls-profile` | `TestClientDoHTTP11ThroughHTTPSProxyConnect` | B: нет HTTPS proxy |
| `TLSProfile.ProxyCheck` | `--proxy-tls-profile-check` | `TestClientDoNonStrictProfileChecksAreIndependent` | B: без proxy profile |
| `TLSProfile.ProxyStrict` | `--proxy-tls-profile-strict` implies ProxyCheck | `TestClientDoStrictProxyTLSProfileMismatchStopsBeforeConnect` | B: без proxy profile; strict mismatch до CONNECT |
| `TLSProfile.ClientHello` | Manual API-only, вместо ProfilePath | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | B: импорт, check, version override, HTTP/3 conflicts |
| `TLSClientHello.Preset` | API-only; CLI base_preset в JSON | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | B: неизвестный preset |
| `TLSClientHello.ServerName` | SNI; fallback Request/URL | `TestClientDoManualTLSClientHelloFieldsOnWire` | B: конфликт с TLSServerName |
| `TLSClientHello.CipherSuites` | Упорядоченный uint16 vector, не native --ciphers | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | Тип Go uint16 IDs; согласование допустимых алгоритмов — TLS handshake |
| `TLSClientHello.SupportedVersions` | Uint16 vector; nil inherits preset | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | Тип Go uint16 IDs; не строковые TLSMinVersion/TLSMaxVersion |
| `TLSClientHello.SupportedGroups` | Uint16 vector; nil inherits preset | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | Тип Go uint16 IDs; требует подходящего extension preset |
| `TLSClientHello.SignatureAlgorithms` | Uint16 vector; nil inherits preset | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | Тип Go uint16 IDs; требует подходящего extension preset |
| `TLSClientHello.ExtensionOrder` | Полная перестановка active extensions | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | B: неизвестный ID; `TestApplyProfileRejectsIncompleteOrDuplicateExtensionOrder` |
| `TLSClientHello.ALPN` | Должен соответствовать HTTP mode | `TestClientDoManualTLSClientHelloExtensionFieldsOnWire` | B: несовместимость; `TestApplyProfileRejectsInvalidALPN` |

## Честные границы

- Native `TLSCipherSuites` управляет набором TLS 1.0–1.2 suites, но не порядком,
  выбираемым `crypto/tls`, и не TLS 1.3 suites. Точное управление vector/order
  относится к manual/imported uTLS-профилю, где оно поддерживается materializer.
- ALPS и явная длина TLS padding в imported JSON пока не материализуются.
  Предпочтение SHOULD по этим полям даёт `PARTIAL_MATCH`, проверяемый реальным
  API handshake (`TestClientDoImportedUnsupportedFieldsReportPartialMatchOnWire`).
  Неподдерживаемый MUST отвергается до сети
  (`TestClientDoRejectsUnsupportedProfileMUSTBeforeNetwork`). Отсутствие ожидания по полю не
  означает обещание воспроизвести его: MATCH относится только к заданной policy.
- Произвольный HTTP/2 HPACK/frame replay, scheduler/окна и QUIC packet replay
  не входят в parity. Матрица не обещает побайтовую идентичность браузера.
- Это локальное доказательство контракта. Fresh remote CI Windows/Linux/macOS
  и длительный fuzz остаются отдельными пунктами 7 и 8 backlog.

## Проверка

Целевой запуск:

```powershell
go test -race ./pkg/gocurl -count=1
```

Полный локальный quality gate:

```powershell
./scripts/check.ps1 -GoExecutable 'C:\Users\Alex\AppData\Local\Programs\Go\1.26.6\bin\go.exe' -LintExecutable 'C:\Users\Alex\go\bin\golangci-lint.exe'
```

Проверено на Windows amd64, Go 1.26.6, GCC w64devkit и golangci-lint 2.10.1.
Полный `scripts/check.ps1` завершился успешно: mod verify, markdownlint,
lint/formatters, vet, race suite с benchmarks, vendored QUIC wire tests и build.
Целевые новые тесты повторены 20 раз с `-race`. Публичные ECH/PQ smoke-тесты
остаются opt-in и не использовались как доказательство этой матрицы.
GitNexus impact для изменённого существующего wire helper: LOW, один прямой
тестовый caller, рабочие процессы не затронуты. Производственный транспортный
код и vendor в этом пункте не изменялись. Новые тесты/документы предназначены
для локального `main`; публикация и тег не входят в данный пункт.
