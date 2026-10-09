# Vendored-патч quic-go

## Назначение

gocurl использует `github.com/quic-go/quic-go` версии `v0.61.0` и хранит
зависимости в `vendor/`. Стандартный `quic-go` не предоставляет все элементы
управления QUIC-отпечатком, необходимые документированному профилю gocurl.
Поэтому vendored-копия содержит небольшой целевой патч.

Сборка и тесты, проверяющие QUIC transport parameters, должны выполняться с
`-mod=vendor`. Без vendored-патча API может компилироваться иначе либо потерять
заданный порядок и явные нулевые значения transport parameters.

## База и изменённые файлы

База патча: неизменённый модуль `github.com/quic-go/quic-go@v0.61.0` из Go
module proxy. По сравнению с этой базой изменены только следующие файлы:

- `config.go` — валидация и materialization дополнительных параметров;
- `connection.go` — передача параметров в client transport и flow control;
- `crypto_stream.go` — callback полного QUIC ClientHello;
- `http3/frames.go` — детерминированная сортировка extension SETTINGS;
- `interface.go` — публичные поля `quic.Config`, используемые gocurl;
- `internal/wire/transport_parameters.go` — детерминированный порядок,
  сохранение GREASE и явных нулевых значений;
- `internal/wire/transport_parameters_order_test.go` — локальные wire-тесты
  патча.

Остальные отличия полного дерева от module cache объясняются обычным pruning,
который выполняет `go mod vendor`: vendored-копия не обязана содержать все
upstream-тесты, примеры и служебные файлы.

## Поддерживаемое поведение

Патч добавляет:

- раздельные initial receive limits для bidi-local, bidi-remote и uni streams;
- `active_connection_id_limit`, `ack_delay_exponent`, `max_ack_delay`,
  `max_udp_payload_size` и `disable_active_migration`;
- приоритетный порядок transport parameter IDs без потери первого GREASE и с
  сохранением относительного порядка неуказанных параметров;
- наблюдение полного ClientHello, включая повторный hello после HRR;
- стабильный порядок дополнительных HTTP/3 SETTINGS.

Патч не является обещанием побайтового воспроизведения произвольного QUIC
capture. Packetization, ACK scheduling, connection IDs, tokens, encryption и
другие динамические значения остаются ответственностью `quic-go`.

## Проверка после обновления зависимости

После изменения версии `quic-go` необходимо заново сравнить vendored-копию с
чистой версией модуля и перенести патч вручную. Затем выполнить:

```text
go mod verify
go test -count=1 -mod=vendor ./...
go test -race -count=1 -mod=vendor ./...
go vet -mod=vendor ./...
go build -mod=vendor ./...
go test -count=1 -mod=vendor -run "Test(ReorderTransportParametersKeepsGreaseAndUnlistedOrder|TransportParametersMarshalUsesConfiguredOrder|TransportParametersMarshalPreservesExplicitZeroValues)$" github.com/quic-go/quic-go/internal/wire
```

Любое новое отличие от upstream должно быть добавлено в список выше и покрыто
локальным wire-тестом.
