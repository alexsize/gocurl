# gocurl changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][keepachangelog], and this project
adheres to [Semantic Versioning][semver].

[keepachangelog]: https://keepachangelog.com/en/1.0.0/

[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- Added a checked API/CLI parity matrix for all public request fields,
  independent validated CLI/API configuration comparisons, and public API
  rejection tests before TCP/UDP dialing or body consumption. Added on-wire
  shared/explicit-zero QUIC windows, independent proxy/target certificate and
  non-strict profile policies, local DNS ECH discovery, exact native cipher-set
  and manual ClientHello vector assertions, and unsupported SHOULD reports.

- Added bounded fuzz targets for HTTP/2 settings and orders, QUIC numeric
  options and parameter order, profile JSON/constraints, and SOCKS UDP target
  addresses. Fixed UDP target ports outside 0..65535 while preserving port zero.
- Corrected duplicated HTTP/1.1 instructions, QUIC ACK/payload option examples,
  HRR report semantics, and the documented local/opt-in test policy.

- Preserved buffered tunnel bytes after HTTP/HTTPS CONNECT, including proxy TLS
  observations. Added coalesced-response regressions for both proxy routes.
- Split TLS/QUIC, proxy negotiation, manual API profile selection, and wire-test
  fixtures without changing protocol behavior or disabling lint rules. Added
  QUIC callback isolation and cancellation checks; all lint findings resolved.
- Stabilized the Windows DNS UDP-to-TCP fixture by reserving both protocols on
  independently selected port candidates and closing failed partial bindings.

- Split ClientHello parsing, JA4 extension collection, and TLS-NORM field
  normalization while retaining golden fingerprints, duplicate-extension
  policies, malformed-input errors, and partial parser results. Added full
  normalization-family regressions and a bounded normalization fuzz target.
- Split QUIC option parsing into focused groups while preserving explicit-zero
  flags, error order, range checks, and partially parsed results on failure.
- Extracted HTTP/2 framing-wrapper selection and covered each activation option;
  default and SETTINGS-value-only connections still use the unwrapped path.

- Split TLS profile validation, materialization, extension application, and
  normalized/constraint checks into focused helpers without changing validation
  order, unsupported-field order, or strict status precedence. Added regression
  tests for slice isolation, ALPN errors, GREASE multiplicity, and padding.
- Consolidated duplicate CLI/API CONNECT and WebSocket fixtures while retaining
  HTTP/HTTPS/SOCKS, WSS, PQ, and strict mismatch coverage. All dupl findings are
  resolved; the existing complexity threshold and enabled linters are unchanged.

- Split API-to-CLI request argument construction into focused builders while
  preserving option order, explicit-zero QUIC settings, and error precedence.
  Added exact argument and validation regression tests.
- Fixed a panic in the QUIC v2 wire-capture test decoder on a payload shorter
  than its packet number; added a malformed-capture regression and fuzz target.
- Added shared checked numeric encoders for ECH/SOCKS test fixtures and removed
  unnecessary signed conversions in QUIC assertions. Classified protocol and
  loopback-fixture gosec findings with narrow, documented annotations; no
  runtime restrictions or broad lint exclusions were added.

- Fixed WebSocket CLI error propagation and preserved frames buffered with the
  HTTP 101 response. Verbose logging now uses the actual request and does not
  regenerate its handshake key or consume file/stdin bodies.
- Preserved partial WebSocket write counts and rejected out-of-range HTTP/2
  PRIORITY weights before writing any bytes. Split HTTP/2 frame processing into
  focused helpers and added write-boundary/continuation wire regressions.
- Added exhaustive GREASE classification, checked TLS fixture lengths and QUIC
  conversion boundary tests; addressed errcheck, revive, staticcheck, unused
  and redundant conversion diagnostics without disabling those linters.

- Added a native Windows quality-gate script with Go/linter compatibility
  checks and explicit executable overrides.
- Quoted benchmark and coverage arguments in CI to prevent PowerShell from
  splitting them and silently narrowing the tested package set.
- Propagated request cancellation and the connection timeout through DNS/ECH
  discovery, HTTP/HTTPS and SOCKS proxy setup, and ClientHello split delays.
  Plain DNS cancellation closes its socket. Legacy encrypted DNS exchanges
  return control immediately on cancellation without closing a shared upstream.
  The library worker can finish later; its configured five-second timeout is
  not a guaranteed total bound across bootstrap, TLS setup, and retries.
- Added local race tests for cancellation during HTTP/2 CONNECT, proxy setup,
  DNS/ECH discovery, and ClientHello split delays, and setup timeout coverage.

- Added local public Go API TLS wire tests for negotiated TLS 1.2 cipher-suite
  selection and the exact 32-byte ClientHello random override.
- Added a local public Go API test that observes the configured ClientHello
  split delay on the socket and completes the subsequent TLS/HTTP exchange.
- Added a public Go API QUIC v2 Initial capture test that decrypts the
  ClientHello and checks requested transport-parameter order on the wire.
- Added a local public Go API custom-DNS IPv6-only test; it skips only when
  IPv6 loopback connections are unavailable or restricted by the host.
- Added a public Go API test proving `ConnectTimeout` bounds a stalled HTTPS
  proxy TLS handshake.
- Added a successful manual TLS ClientHello API wire test covering SNI, ALPN,
  TLS version, and cipher-suite negotiation.
- Added a manual TLS ClientHello API wire test for supported groups, signature
  algorithms, and caller-specified extension order.
- Reuse one HTTP/1.1 TLS connection for OHTTP keys and gateway requests when
  both URLs have the same origin. Strict TLS-profile mode reports the reused
  gateway connection as `REUSED_CONNECTION` (exit code 5); local integration
  tests cover the actual socket reuse in the transport, public Go API, and CLI
  JSON output.
- Added a real strict TLS-profile mismatch CLI subprocess test. It verifies
  `MISMATCH` in JSON and stderr, exit code 4, and confirms the HTTP handler was
  never reached.
- Added a successful local TLS CLI JSON test that verifies the observed target
  connection includes non-empty JA3 and JA4 fingerprints with status `OBSERVED`.
- Added a local ECH GREASE CLI subprocess test that verifies a successful HTTP
  response reports `NOT_OBSERVED` without fabricating an actual fingerprint.
- Added a bounded fuzz target for header-file parsing with valid, empty,
  malformed UTF-8, CR/LF injection, and missing-delimiter seeds.
- Added public Go API OHTTP route coverage through local HTTP, HTTPS, SOCKS5,
  and SOCKS5H proxies. The test verifies the decrypted target URL and one reused
  OHTTP connection per route.
- Added public Go API WSS route coverage for direct, HTTP, HTTPS, SOCKS5, and
  SOCKS5H. The local TLS WebSocket fixture verifies target SNI and Host,
  `Sec-WebSocket-Accept`, and a masked client frame with its server response.
- Added public Go API post-quantum TLS route coverage for direct, HTTP, HTTPS,
  SOCKS5, and SOCKS5H. The test verifies X25519MLKEM768 negotiation at the TLS
  target, the request Host/SNI, and SOCKS address type.
- Added public Go API accepted-ECH route coverage for direct, HTTP, HTTPS,
  SOCKS5, and SOCKS5H. A local ECH-enabled TLS server with an ephemeral HPKE key
  verifies that ECH was accepted and the request reached the intended route.
- Added public Go API checks that WebSocket requests explicitly reject HTTP/2
  and HTTP/3 before opening a network connection; documented the HTTP/3, WebSocket,
  manual ClientHello, and post-quantum transport compatibility matrix in the TZ.
- Added a public Go API regression test confirming that separate HTTP/1.1 calls
  from one `Client` establish separate target TLS connections, as documented in
  the connection-reuse policy.
- Added a README/CLI option-set parity test and documented the four previously
  omitted flags for JSON header redaction and QUIC transport controls.
- Added a contract table for all public `Request` fields, including CLI mapping,
  zero/nil behavior, constraints, and regression-test references. Automated tests
  now ensure every field and cited test stays represented in the README.
- Aligned all README CLI option descriptions with their `config.Options` tags
  and added a regression test that detects description drift per flag.
- Added a public Go API HTTP/2 wire test that checks the actual initial SETTINGS
  values and their configured order against a local TLS listener.
- Added a public Go API HTTP/2 framing test that checks DATA chunk size,
  HEADERS/CONTINUATION fragmentation and padding, pseudo/regular header order,
  and the emitted PRIORITY frame on the wire.
- Added a public Go API HTTP/3 wire test for additional SETTINGS, explicit-zero
  values, setting order, and datagram negotiation on a local QUIC listener.
- Added a public Go API QUIC listener test for negotiated transport parameter
  values, initial packet size, source connection ID length, and QUIC v2.
- Added local CLI and public Go API tests for a genuinely interrupted
  ClientHello write. An incomplete capture now retains status `INCOMPLETE` and
  exit code 5 instead of being overwritten by the generic connection error.
- Replaced mandatory CLI OHTTP calls to a public demo service with local
  key-config and gateway fixtures, including the proxy path. Public Cloudflare
  ECH/PQ smoke tests remain explicitly opt-in.
- Added process-level CLI and public Go API regression tests proving that an
  unsupported imported TLS profile is rejected before dialing, with CLI JSON
  status `UNSUPPORTED` and exit code 2.
- Added local CLI and public Go API handshake-failure tests proving that a TCP
  connection followed by an aborted TLS capture reports `CONNECTION_ERROR` and
  exit code 3.
- Added a process-level strict profile test proving that `PARTIAL_MATCH` is
  serialized to CLI JSON, logged to stderr, exits with code 4, and prevents the
  HTTP request after the TLS handshake.
- Added CLI subprocess coverage for binary stdin and file bodies across a 307
  response, proving exact bytes, streaming/known lengths, one request only, and
  returning the first redirect without automatic retry.
- Added public Go API tests for cancellation during a streaming upload and a
  body reader failure, proving prompt error propagation and a single network
  attempt.
- Added QUIC ClientHello fingerprint reporting and strict profile checking for
  HTTP/3. A local integration test verifies observed JA3/JA4/ALPN and that a
  strict mismatch aborts the request.
- Added capture of the post-HelloRetryRequest QUIC ClientHello. Reporting and
  strict modes now wait for handshake completion, report every observed hello
  with its index, and evaluate all of them before allowing an HTTP/3 request.
- Added manual ClientHello profiles to the public Go API, including preset,
  server name, cipher suites, ALPN, versions, groups, signature algorithms, and
  extension order. Profiles are validated before dialing and their actual
  on-wire fingerprints remain available in `Result.TLSReports`.
- Added opt-in HTTP/2 CONNECT tunnels for HTTPS proxies via
  `--proxy-http2-connect` and the Go request API. Requires `h2` ALPN and is
  covered by a local full-duplex CONNECT stream test.
- Added a local SOCKS5-to-TLS integration test proving that the configured
  target ClientHello is captured and its ALPN is preserved through the tunnel.
- Added HTTP/2 client SETTINGS controls and HTTP/3 extension SETTINGS for CLI
  and Go API, with strict validation and local wire-capture tests. QUIC transport
  fingerprint remains only partially configurable; HTTP/2 frame/header controls
  are listed below.
- Added QUIC v1/v2 selection, initial receive windows, idle timeout, and
  incoming-stream limits for HTTP/3. A server-side QUIC trace verifies received
  transport parameters; an end-to-end HTTP/3 test verifies request delivery.
- Added standard HTTP/3 Datagrams negotiation, verifying both HTTP/3 SETTINGS
  and the corresponding QUIC transport parameter on local connections.
- Added a configurable QUIC Initial packet size and server-side qlog assertion
  for the received Initial datagram length.
- Added explicit HTTP/2 initial SETTINGS order and request pseudo-header order
  for CLI and Go API, with on-wire frame/HPACK assertions and an end-to-end
  request test covering CONTINUATION frames and a POST body.
- Added an HTTP/2 outbound DATA payload-size cap with local frame capture and
  end-to-end POST coverage.
- Added explicit ordering of regular HTTP/2 request header fields, preserving
  repeated values and verifying the decoded order from a captured HEADERS block.
- Allowed explicit HTTP Host overrides and empty User-Agent values on the wire,
  with early validation of CLI headers and duplicate Host fields.
- Added an explicit HTTP/1.1 request-target override for CLI and Go API that
  preserves the URL used for dialing and TLS.
- Added `--no-default-headers` and a Go API equivalent for suppressing gocurl's
  automatic User-Agent and form Content-Type in HTTP/1.1 requests.
- Added UTF-8 `--header-file` parsing and HTTP/1.1 wire serialization that
  preserves specified header order, repeated fields, and field-name casing.
- Added public Go API v1 in `pkg/gocurl` with ordered request headers, streaming
  request bodies, TLS profile options, structured connection reports, and
  explicit response/transport cleanup.
- Added JA3Proxy-compatible `TLS-NORM-1` ClientHello normalization and SHA-256
  profile comparison, with unsupported results for malformed normalized fields
  or unknown normalization versions.
- Added the v1 JA3Proxy client-profile JSON Schema, strict Go profile decoder,
  golden fixtures, and explicit unsupported-field reporting for uTLS materialization.
- Added `--tls-profile` to import a JA3Proxy profile for HTTPS TCP requests and
  apply its uTLS preset/ALPN; unsupported MUST fields and incompatible modes
  fail before dialing, while unsupported optional fields are reported.
- Added `--tls-profile-check` and `--tls-profile-strict` to compare fingerprints
  from the ClientHello actually written on the connection; checks report
  structured JA3/JA4 and supported-field differences.
- Added per-request TLS connection reports to JSON responses when profile
  checking is enabled, including observed fingerprints for HTTP/1.1 and HTTP/2.
- Added a distinct `gateway` TLS connection report for OHTTP JSON responses;
  the decrypted target response is not misrepresented as the TLS peer.
- Added an independent TLS profile and actual-ClientHello check for HTTPS proxy
  connections; strict mismatches stop before sending the CONNECT request, and
  HTTP/1.1 is the default CONNECT protocol; HTTP/2 CONNECT requires explicit
  `--proxy-http2-connect` and an `h2` ALPN profile.
- Added `--data-binary @<file>` and `--data-binary @-` for unmodified streaming
  request bodies; regular files use their exact content length and stdin is
  streamed without being consumed by verbose request logging.
- Added materialization and wire-based checking for profile cipher suites,
  supported TLS versions, supported groups, and signature algorithms; optional
  exporter-marked non-replayable values remain explicitly unsupported.
- Added documented exit codes for profile-check failures and structured JSON
  error fields carrying the same status and exit code.
- Added an isolated uTLS handshake spike with preset/custom extension-order,
  ALPN overrides, and capture of the ClientHello bytes actually written.

### Changed

- Aligned Make and CI quality gates on vendored module verification, race
  tests, vet, all-package builds, vendored QUIC wire tests, linters, and a clean
  checkout check after CI execution.
- Pinned CI to Go 1.26.5 from `go.mod`; using the moving `stable` alias could
  select a toolchain newer than golangci-lint's supported export-data format.
- Limited markdownlint to project-owned documentation so vendored upstream and
  generated directories do not make the quality gate nondeterministic.
- Corrected repository guidance to identify `pkg/gocurl` as the public Go API
  and linked the vendored QUIC patch documentation from the development guide.
- Documented the exact `quic-go v0.61.0` vendor patch, its supported behavior,
  upgrade procedure, and wire-test gate. Local Go caches, captures, private
  keys, databases, and test binaries are now explicitly ignored.
- Reworked the JA3Proxy extension specification after a code, test, route,
  status, documentation, and CI audit. The prioritized backlog now separates
  verified protocol subsets from missing end-to-end and release evidence.

### Fixed

- Reject post-quantum TLS with an imported target TLS profile or HTTP/3 before
  network access, consistently for CLI and the public Go API.
- Apply the connection timeout to target TLS and QUIC handshakes, close failed
  connections, and detach the timer after successful establishment.
- Preserve request cancellation and deadlines across the detached TLS dial
  context used by Go's HTTP transport. Local CLI/API race tests cover stalled
  handshakes, cancellation, and response reads longer than the connect timeout.

[unreleased]: https://github.com/ameshkov/gocurl/compare/v1.6.0...HEAD

## [1.6.0] - 2026-08-08

### Added

- Added `make init` that installs a git pre-commit hook checking for temporary
  TODOs and running linters and tests.

### Changed

- Updated dependencies, now using newer versions of `quic-go` (v0.61.0),
  `dnsproxy` (v0.83.2), `golibs` (v0.35.15), and other dependencies.  The Go
  version required by the module is now 1.26.5.
- Adapted the code to the newer `quic-go` API: `http3.RoundTripper` is now
  `http3.Transport`, and `DialQUIC` returns `*quic.Conn` instead of
  `quic.EarlyConnection`.

[See changes][1.6.0changes].

[1.6.0changes]: https://github.com/ameshkov/gocurl/compare/v1.5.2...v1.6.0

[1.6.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.6.0

## [1.5.2] - 2026-05-22

- Preserve original Content-Type in OHTTP requests

[See changes][1.5.2changes].

[1.5.2changes]: https://github.com/ameshkov/gocurl/compare/v1.5.1...v1.5.2

[1.5.2]: https://github.com/ameshkov/gocurl/releases/tag/v1.5.2

## [1.5.1] - 2026-02-25

### Fixed

- Fixed using `--http3` together with `--connect-to`.
- Fixed unexpected panic when the server stops responding unexpectedly.
- Fixed OHTTP responses not being written to the output.

[See changes][1.5.1changes].

[1.5.1changes]: https://github.com/ameshkov/gocurl/compare/v1.5.0...v1.5.1

[1.5.1]: https://github.com/ameshkov/gocurl/releases/tag/v1.5.0

## [1.5.0] - 2025-10-13

### Added

- Added `--connect-timeout` command-line argument support. ([#43][#43])
- Added `--ohttp-gateway-url` and `--ohttp-keys-url` command-line arguments. ([#44][#44])

[#43]: https://github.com/ameshkov/gocurl/issues/43

[#44]: https://github.com/ameshkov/gocurl/issues/44

[See changes][1.5.0changes].

[1.5.0changes]: https://github.com/ameshkov/gocurl/compare/v1.4.9...v1.5.0

[1.5.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.5.0

## [1.4.9] - 2025-05-19

### Fixed

- Fixed the issue with `--tls-random` when it's used with `--ech`. ([#38][#38])

[See changes][1.4.9changes].

[#38]: https://github.com/ameshkov/gocurl/issues/38

[1.4.9changes]: https://github.com/ameshkov/gocurl/compare/v1.4.8...v1.4.9

[1.4.9]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.9

## [1.4.8] - 2025-05-13

### Added

- Added support for `--tls-random` command-line argument. This option is used to
  enable TLS Random for TLS ClientHello. ([#35][#35])

[See changes][1.4.8changes].

[#35]: https://github.com/ameshkov/gocurl/issues/35

[1.4.8changes]: https://github.com/ameshkov/gocurl/compare/v1.4.7...v1.4.8

[1.4.8]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.8

## [1.4.7] - 2025-04-02

### Added

- Added support for `--echgrease` command-line argument. This option is used to
  enable ECH Grease for TLS ClientHello.

[See changes][1.4.7changes].

[1.4.7changes]: https://github.com/ameshkov/gocurl/compare/v1.4.6...v1.4.7

[1.4.7]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.7

## [1.4.6] - 2025-03-21

### Fixed

- Cannot set User Agent via headers. ([#34][#34])
- `--insecure` flag is not respected by DNS upstreams. ([#30][#30])

[See changes][1.4.6changes].

[#30]: https://github.com/ameshkov/gocurl/issues/30

[#34]: https://github.com/ameshkov/gocurl/issues/34

[1.4.6changes]: https://github.com/ameshkov/gocurl/compare/v1.4.5...v1.4.6

[1.4.6]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.6

## [1.4.5] - 2025-03-17

### Added

- Added `http` and `https` proxies support. ([#31][#31])

### Fixed

- Panic when `--json-output` is specified and failed to read response body.

[See changes][1.4.5changes].

[#31]: https://github.com/ameshkov/gocurl/issues/31

[1.4.5changes]: https://github.com/ameshkov/gocurl/compare/v1.4.4...v1.4.5

[1.4.5]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.5

## [1.4.4] - 2025-03-13

### Changed

- Updated dependenceis.
- `--ech` no more fails when there's no ECH configuration for the domain, it
  just falls back to regular TLS and prints a warning.
- Use MLKEM for post-quantum key exchange when `--experiment` is used.

[See changes][1.4.4changes].

[1.4.4changes]: https://github.com/ameshkov/gocurl/compare/v1.4.3...v1.4.4

[1.4.4]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.4

## [1.4.3] - 2024-06-04

### Added

- Added support for the `--tls-servername` argument.

### Changed

- Use `http` as the default scheme.  ([#27][#27])
- Updated dependencies, now using newer versions of quic-go, dnsproxy, cfcrypto.

[See changes][1.4.3changes].

[1.4.3changes]: https://github.com/ameshkov/gocurl/compare/v1.4.2...v1.4.3

[1.4.3]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.3

[#27]: https://github.com/ameshkov/gocurl/issues/27

## [1.4.2] - 2024-03-31

### Added

- Added support for the `--tls-max` argument.
- Added support for the `--ciphers` argument.

[See changes][1.4.2changes].

[1.4.2changes]: https://github.com/ameshkov/gocurl/compare/v1.4.1...v1.4.2

[1.4.2]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.2

## [1.4.1] - 2024-02-07

### Added

- Added support for `--ipv4` and `--ipv6` arguments.  ([#25][#25])
- Added [a Docker image][dockerimage] for `gocurl`.

### Fixed

- Fixed a bug introduced in v1.4.0 with `gocurl` not printing the response body
  when the protocol is HTTP/2 or HTTP/3.  ([#26][#26])
- Fixed unnecessary warning `connection doesn't allow setting of receive buffer
  size` when HTTP/3 is used.

[See changes][1.4.1changes].

[1.4.1changes]: https://github.com/ameshkov/gocurl/compare/v1.4.0...v1.4.1

[1.4.1]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.1

[dockerimage]: https://github.com/ameshkov/gocurl/pkgs/container/gocurl

[#25]: https://github.com/ameshkov/gocurl/issues/25

[#26]: https://github.com/ameshkov/gocurl/issues/26

## [1.4.0] - 2024-02-04

### Added

- Added initial WebSocket support. `gocurl` now supports `ws://` and `wss://`
  URLs. `-d` can be used to specify initial data to send.  ([#17][#17])

[See changes][1.4.0changes].

[1.4.0changes]: https://github.com/ameshkov/gocurl/compare/v1.3.0...v1.4.0

[1.4.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.4.0

[#17]: https://github.com/ameshkov/gocurl/issues/17

## [1.3.0] - 2023-09-23

### Added

- Added an option to use Post-Quantum secure algorithms for establishing TLS
  connections. This option is hidden under a new `--experiment` flag that is
  described in README.md. ([#15][#15])

### Fixed

- Fixed an issue with `--http2` not being able to work together with `--ech`. In
  addition to that there's also one more change: `gocurl` by default will send
  both `h2` and `http/1.1` in TLS ALPN extension and use the protocol selected
  by the server. ([#14][#14])

[See changes][1.3.0changes].

[1.3.0changes]: https://github.com/ameshkov/gocurl/compare/v1.2.0...v1.3.0

[1.3.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.3.0

[#14]: https://github.com/ameshkov/gocurl/issues/14

[#15]: https://github.com/ameshkov/gocurl/issues/15

## [1.2.0] - 2023-09-22

### Added

- Added `--dns-servers` command-line argument support. Besides regular DNS,
  `gocurl` also supports encrypted DNS, see examples in README.md to learn
  more. ([#6][#6])

### Fixed

- TLS state is now printed to the output for ECH-enabled connections. In
  addition to that, much more TLS-related information is printed to the output
  including information about TLS certificates. ([#8][#8])

[See changes][1.2.0changes].

[1.2.0changes]: https://github.com/ameshkov/gocurl/compare/v1.1.0...v1.2.0

[1.2.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.2.0

[#6]: https://github.com/ameshkov/gocurl/issues/6

[#8]: https://github.com/ameshkov/gocurl/issues/8

## [1.1.0] - 2023-09-21

### Added

- `gocurl` now supports Encrypted Client Hello. Added `--ech` and `--echconfig`
  command-line arguments, see examples in README.md to learn more. ([#3][#3])
- Added `--resolve` command-line argument support. It works similarly to the one
  in `curl` with one important difference: `gocurl` ignores `port` there and
  simply returns specified IP addresses for the host. ([#5][#5])

[See changes][1.1.0changes].

[1.1.0changes]: https://github.com/ameshkov/gocurl/compare/v1.0.6...v1.1.0

[1.1.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.1.0

[#3]: https://github.com/ameshkov/gocurl/issues/3

[#5]: https://github.com/ameshkov/gocurl/issues/5

## [1.0.6] - 2023-09-17

### Added

- `--connect-to` and `--proxy` now also support HTTP/3. ([#1][#1])

[See changes][1.0.6changes].

[1.0.6changes]: https://github.com/ameshkov/gocurl/compare/v1.0.5...v1.0.6

[1.0.6]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.6

[#1]: https://github.com/ameshkov/gocurl/issues/1

## [1.0.5] - 2023-09-15

### Added

- Added the changelog.

### Changed

- Added more debug logging to all request stages.

### Fixed

- Fixed the way `--connect-to` works when a proxy is specified. Before this
  change gocurl could only redirect the proxy connection, but not the one that
  goes through proxy. This behavior is now fixed.

[See changes][1.0.5changes].

[1.0.5changes]: https://github.com/ameshkov/gocurl/compare/v1.0.4...v1.0.5

[1.0.5]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.5

## [1.0.4] - 2023-09-12

### Fixed

- Fixed the issue with the output being written not to stdout by default.

[See changes][1.0.4changes].

[1.0.4changes]: https://github.com/ameshkov/gocurl/compare/v1.0.3...v1.0.4

[1.0.4]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.4

## [1.0.3] - 2023-09-12

### Fixed

- Minor improvements.

[See changes][1.0.3changes].

[1.0.3changes]: https://github.com/ameshkov/gocurl/compare/v1.0.2...v1.0.3

[1.0.3]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.3

## [1.0.2] - 2023-09-12

### Added

- Automate the release process.

[See changes][1.0.2changes].

[1.0.2changes]: https://github.com/ameshkov/gocurl/compare/v1.0.1...v1.0.2

[1.0.2]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.2

## [1.0.1] - 2023-09-12

### Fixed

- Logging improvements.

[See changes][1.0.1changes].

[1.0.1changes]: https://github.com/ameshkov/gocurl/compare/v1.0.0...v1.0.1

[1.0.1]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.1

## [1.0.0] - 2023-09-12

### Added

- The first version with base functionality.

[1.0.0]: https://github.com/ameshkov/gocurl/releases/tag/v1.0.0
