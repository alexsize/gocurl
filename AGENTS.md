# AGENTS.md

Single-binary Go CLI (`gocurl`, a curl-like tool with ECH, encrypted DNS,
OHTTP, and WebSocket extras). Module `github.com/ameshkov/gocurl`, Go 1.26.5 —
the local toolchain must match `go.mod`. Most implementation code is under
`internal/`; the versioned public Go API is `pkg/gocurl`. There is no second
module.

## Commands

- `make init` — installs the git pre-commit hook (it is NOT installed by
  default on clone). The hook blocks commits containing `FIXME` or `TODO!!` in
  staged non-doc files and then runs `make check`.
- `make check` — the CI quality gate: `make lint` then `make test`. This is what
  the pre-commit hook and CI run; mirror it before finishing work.
- `make lint` — `npx markdownlint-cli .` (needs Node.js; config in
  `.markdownlint.json`) then `golangci-lint run`.
- `make test` — `go test -race -v -bench=. ./...` (runs benchmarks too, slow).
  For a fast iteration loop use `go test ./internal/...` or
  `go test -run <TestName> ./internal/cmd`.
- `make build` / `make release` — release requires `GOOS`, `GOARCH`, `VERSION`
  env vars (see CI `build.yaml` for the full cross-compile matrix).
- `golangci-lint run --fix` applies the configured formatters.

## Formatting (lint fails otherwise)

- `.golangci.yml` (golangci-lint v2) enables the `gofumpt`, `goimports`, and
  `golines` formatters with `max-len: 120`. Keep lines <=120 chars and
  gofumpt-formatted; there is no standalone gofmt step.
- AdGuard-team doc-comment style (`// Package name ...`, sentence-per-paragraph
  style) is used throughout; match existing files.
- Any markdown you touch (including this file) must pass markdownlint: dashed
  list markers, 4-space nested indentation, asterisk emphasis; line-length and
  bare-URL checks are disabled.

## Architecture

- Entry flow: `main.go` -> `internal/cmd.Main()` -> `config.ParseConfig` ->
  `output.NewOutput` -> `cmd.Run(cfg, out)`. `Run` is extracted for testability.
  Command tests call it directly; CLI contract tests also execute a locally
  built binary to verify JSON, stderr, and exit codes.
- Two config layers: raw go-flags tags live in `internal/config/options.go`
  (`Options`); `ParseConfig` validates them into the typed `Config` in
  `internal/config/config.go`. To add a CLI flag: add a tagged field in
  `Options`, plumb it in `ParseConfig`, and update the "All command-line
  arguments" block in `README.md`, which mirrors the `--help` text generated
  from those tags.
- `internal/client` — HTTP transport, dialer, proxy, plus feature packages:
  `ohttp`, `websocket`, `splittls`, `cfcrypto` (ECH), `connectto`.
  `internal/resolve` owns DNS resolution and ECH-config discovery;
  `internal/output` writes results; `internal/appversion` holds the linker-set
  version.
- `cmd.Run` hand-rolls response body-readability with a large conditional, and
  special-cases WebSocket upgrade. Read that function before touching response
  handling.

## Testing

- Command-level tests (`internal/cmd/cmd_test.go`) spin up a local
  `httptest.NewServer(httpbin.New().Handler())` and call
  `cmd.Run(cfg, out)` with `config.ParseConfig(args)` plus a buffer-backed
  `output.NewOutputWithWriters(...)`. New tests should be fully local and
  hermetic.
- Mandatory OHTTP and resolver tests use local HTTP/DNS fixtures. Public-network
  ECH/PQ smoke tests are opt-in with `GOCURL_NETWORK_INTEGRATION=1`; keep them
  outside the default quality gate.

## Releases

- Version is injected at link time via
  `-ldflags "-X github.com/ameshkov/gocurl/internal/appversion.version=$(VERSION)"`
  (Makefile and Dockerfile); `appversion.Version()` falls back to `v0.0` when
  unset.
- Version bumps are dedicated commits ("Bump version to vX.Y.Z") with a
  CHANGELOG.md entry (Keep a Changelog; update the `[Unreleased]` block).
- Releasing = push a `v*` tag. CI builds the cross-OS archive matrix and uploads
  it as a GitHub release, and builds/pushes a multi-arch Docker image (on tags
  and `master`).

## Guidelines

- In the JA3Proxy workspace, this gocurl checkout is `C:\ja3proxy\gocurl`; do not use the former temporary checkout, and keep work on `main`.
- When bumping the Go version, update it in `go.mod` first (source of truth),
  then the `golang:...` image tag in `Dockerfile` and the version mention in the
  intro of this file. CI workflows use `go-version: stable` and need no edit.
- Add new guidelines to this "Guidelines" section automatically whenever you are
  asked to add a guideline, or infer from the conversation that a correction
  deserves to be codified as one. Keep each guideline concise and actionable.
- Whenever a task is user-facing or otherwise important, add a brief description
  of it to the `[Unreleased]` block of `CHANGELOG.md`, following the Keep a
  Changelog format (e.g. under `### Added` / `### Changed` / `### Fixed`).

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **gocurl** (2631 symbols, 8781 relationships, 195 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/gocurl/context` | Codebase overview, check index freshness |
| `gitnexus://repo/gocurl/clusters` | All functional areas |
| `gitnexus://repo/gocurl/processes` | All execution flows |
| `gitnexus://repo/gocurl/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
