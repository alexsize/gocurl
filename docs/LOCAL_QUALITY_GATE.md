# Локальный quality gate: Windows и WSL

Дата: 12 октября 2026 года. Репозиторий: `C:\ja3proxy\gocurl`, ветка `main`.
Пункт 7 backlog, после уточнения пользователя: проверять только этот компьютер,
Windows и локальную Ubuntu WSL. GitHub runners и другие компьютеры не запускать.
Установка инструментов в WSL разрешена пользователем.

## Изменения

- Go и Markdown lint перенесены в обязательный `tests` job Build workflow.
  Packaging зависит от этого job и не запускается при ошибке lint. Отдельный
  дублирующий `.github/workflows/lint.yaml` удалён; он восстановим из Git.
- Workflow берёт версию Go из `go.mod`, задаёт локальный toolchain и отключает
  публичные opt-in smoke-тесты. Matrix fail-fast выключен, чтобы один сбой не
  отменял диагностику других платформ при будущем явно разрешённом CI run.
  Ручной `workflow_dispatch` предусмотрен, но в этой проверке не использован.
- Makefile, PowerShell gate и workflow включают module verify, Markdown/Go lint,
  vet, обычные тесты, race-тесты с benchmarks, vendored QUIC wire-тесты и build.
- `scripts/check.ps1` использует платформенный PATH separator, ограничивает
  Windows-specific discovery Windows-платформой и корректно ищет Linux linter.
  Исходные PATH, GOTOOLCHAIN и рабочая директория восстанавливаются в finally.
- `TestQualityGateContractsStayAligned` сверяет YAML с локальными gate commands,
  обязательность проверок и зависимость release packaging. Девять отрицательных
  сценариев ловят удалённые/необязательные проверки, Linux-only lint, bypass
  release gate, fail-fast и самостоятельный drift версии Go. Это статический
  guard контракта, не эмулятор GitHub Actions.
- В `go.mod` исправлены только direct/indirect classifications для уже
  использованных `circl` и `yaml.v3`; версии зависимостей не обновлялись.
- Исправлена гонка SOCKS deadline: если socket timeout уже наступил и deadline
  context истёк, сохраняется `context.DeadlineExceeded`, даже когда callback
  таймера ещё не обновил `ctx.Err()`. Независимый socket timeout до deadline,
  EOF, успешное соединение и явная отмена сохраняют прежнюю семантику.
  Общий `connectionPhaseError` с CRITICAL impact не изменялся. SOCKS DialContext
  имеет LOW impact по GitNexus: один прямой caller и один затронутый процесс;
  interface callers дополнительно покрываются полными CLI/API тестами.
  Детерминированная регрессия повторена 100 раз с race detector на Windows;
  реальный `TestRunConnectTimeout` — 20 раз с race detector в WSL.

## Инструменты WSL

Установка выполняется в локальную `Ubuntu-24.04`, x86_64:

```powershell
wsl -d Ubuntu-24.04 -u root --exec bash /mnt/c/ja3proxy/gocurl/scripts/install-wsl-tools.sh
```

Скрипт устанавливает нативные Linux инструменты в `/opt/gocurl-toolchains`
и создаёт ссылки в `/usr/local/bin`, не заменяя существующие чужие программы.
В архив существующей установки ничего не распаковывается. SHA-256 проверяется
до распаковки. Downloads остаются в указанной скриптом `/tmp/gocurl-tools-*`.

| Инструмент | Версия | Источник |
| --- | --- | --- |
| Go | 1.26.6 linux/amd64 | Официальный [Go download/install](https://go.dev/doc/install); SHA-256 из release metadata |
| Node.js | 24.21.0 | [nodejs.org](https://nodejs.org/dist/v24.21.0/); SHASUMS256.txt |
| Markdownlint CLI | 0.49.1 | npm package `markdownlint-cli`, точная версия |
| golangci-lint | 2.10.1, built with go1.26.0 | Официальный [release](https://github.com/golangci/golangci-lint/releases/tag/v2.10.1), asset SHA-256 |
| PowerShell | 7.6.6 Linux x64 | Официальный [release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.6), asset SHA-256 |
| GCC, make, git | Уже установлены в WSL | Повторная установка не требовалась |

Это Linux executables, а не Windows Go/Node через WSL interop. Native Linux
lint успешно проходит с указанной сборкой; совпадение patch-версий Go и
toolchain линтера не объявляется необходимым само по себе.

## Запуск

Windows, с нативным GCC в PATH:

```powershell
$env:PATH = 'C:\w64devkit\bin;' + $env:PATH
./scripts/check.ps1 -GoExecutable 'C:\Users\Alex\AppData\Local\Programs\Go\1.26.6\bin\go.exe' -LintExecutable 'C:\Users\Alex\go\bin\golangci-lint.exe'
```

WSL, с native Linux PowerShell и инструментами:

```powershell
wsl -d Ubuntu-24.04 --exec pwsh -NoProfile -File /mnt/c/ja3proxy/gocurl/scripts/check.ps1 -GoExecutable /usr/local/bin/go -LintExecutable /usr/local/bin/golangci-lint
```

Для независимого checkout используйте локальный clone коммита `main` в
отдельную новую директорию. На Linux предпочтителен native filesystem WSL,
а не тестирование Windows executables. После gate проверьте:

```shell
git status --porcelain --untracked-files=all
```

Результат должен быть пустым. Папки toolchain и downloads не входят в исходники,
а локальные рабочие изменения не следует «чистить» с помощью reset/clean.

## Результаты и границы

Полные gate прошли на рабочих деревьях Windows/WSL и повторно из независимых
local clone коммита `f1a0a89b010fc5598c3f935fe8f087e89fdba7f1`:

| Среда | Независимый checkout | Результат |
| --- | --- | --- |
| Windows amd64 | `C:\Users\Alex\AppData\Local\Temp\gocurl-gate-20261012-4888dde863a04bfd807c0fe913d20435` | `WINDOWS_CLEAN_CHECKOUT_GATE_PASS` |
| Ubuntu 24.04 WSL, Linux amd64, native filesystem | `/home/sw/gocurl-gate-20261012-ca7rM1iU` | `WSL_CLEAN_CHECKOUT_GATE_PASS` |

В обеих средах прошли module verification, Markdownlint, Go lint с 0 issues,
vet, обычные тесты без race instrumentation, race suite с benchmarks,
vendored QUIC wire tests и all-package build. После gate `git status
--porcelain --untracked-files=all` пустой; untracked исходники для прохождения
не нужны. `go mod tidy -diff` в рабочем checkout также не обнаружил расхождений.
Это не обещание offline build с пустыми module/tool caches.

GitNexus staged review: MEDIUM, 55 изменённых символов, три ожидаемых SOCKS
процесса. Изменение общего CRITICAL обработчика таймаутов не потребовалось.
Пункт 7 закрыт в явно уточнённой пользователем локальной области приёмки.
В goCURL backlog остаются пункты 8, 9, 10.

macOS и hosted GitHub Actions не проверяются по прямому указанию пользователя;
их конфигурация сохранена для будущего отдельно разрешённого запуска.
Публикация разрешена только в `alexsize/gocurl/main`, без тегов. При push
используется поддержанный GitHub [маркер `[skip ci]`](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs),
чтобы не запускать проверки на других компьютерах.
Корневой JA3Proxy этим изменением не публикуется и не модифицируется.
