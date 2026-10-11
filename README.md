# gocurl

[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/gocurl)](https://goreportcard.com/report/ameshkov/gocurl)
[![Latest release](https://img.shields.io/github/release/ameshkov/gocurl/all.svg)](https://github.com/ameshkov/gocurl/releases)

[`curl`](https://curl.se/) compatible tool written in Go that focuses on
features curl does not provide.

1. Supports a subset of curl options needed for its use cases.
2. Adds flags that curl does not support.
   [Read more about the new stuff](#newstuff).

- [Why in the world you need another curl?](#why)
- [How to install gocurl?](#install)
- [How to use gocurl?](#howtouse)
- [New stuff](#newstuff)
    - [Encrypted ClientHello](#ech)
    - [Custom DNS servers](#dns)
    - [Oblivious HTTP](#ohttp)
    - [Experimental flags](#exp)
        - [Post-quantum cryptography](#pq)
    - [WebSocket support](#websocket)
- [Development](#development)
- [All command-line arguments](#allcmdarguments)

<a id="why"></a>

## Why in the world you need another curl?

Curl is certainly awesome, but sometimes I need to have better control over
what's happening on the inside and to be able to debug it. It seemed easier to
me to implement the necessary parts of curl in Go.

Also, I'd like to be able to extend it with what fits my specific needs.
Unfortunately, curl is a bit too huge for that now.

<a id="install"></a>

## How to install gocurl?

- Using homebrew:

    ```shell
    brew install ameshkov/tap/gocurl
    ```

- From source:

    ```shell
    go install github.com/ameshkov/gocurl@latest
    ```

- You can use [a Docker image][dockerimage]:

    ```shell
    docker run --rm ghcr.io/ameshkov/gocurl --help
    ```

- You can get a binary from the [releases page][releases].

[dockerimage]: https://github.com/ameshkov/gocurl/pkgs/container/gocurl

[releases]: https://github.com/ameshkov/gocurl/releases

<a id="howtouse"></a>

## How to use gocurl?

Use it the same way you use original curl.

- `gocurl https://httpbin.agrd.workers.dev/get` make a `GET` request.
- `gocurl -d "test" -v https://httpbin.agrd.workers.dev/post` make a `POST`
  request with `test` data.
- `gocurl -I https://httpbin.agrd.workers.dev/head` make a `HEAD` request.
- `gocurl -I --insecure https://expired.badssl.com/` do not verify TLS
  certificate.
- `gocurl -I --http1.1 https://httpbin.agrd.workers.dev/head` force use
  HTTP/1.1.
- `gocurl -I --http2 https://httpbin.agrd.workers.dev/head` force use HTTP/2.
- `gocurl -I --http3 https://httpbin.agrd.workers.dev/head` force use HTTP/3.
- `gocurl -x socks5://user:pass@host:port https://httpbin.agrd.workers.dev/get`
  use a proxy server.
- `gocurl --proxy-insecure -x https://proxy.example.test:8443 https://example.test/`
  skip certificate verification for the HTTPS proxy only; target certificate
  verification remains enabled unless `--insecure` is also specified.
- `gocurl -I --tlsv1.3 https://tls-v1-2.badssl.com:1012/` force use TLS v1.3.
- `gocurl -I --connect-to "httpbin.agrd.workers.dev:443:172.67.152.85:443"
  https://httpbin.agrd.workers.dev/head` connect to the specified IP addresses.
- `gocurl -I --resolve "httpbin.agrd.workers.dev:443:172.67.152.85"
  https://httpbin.agrd.workers.dev/head` resolve the hostname to the specified
  IP address. Note, that unlike `curl`, `gocurl` ignores port in this option.
- `gocurl -I --connect-timeout 3 http://10.255.255.1:9999/test`
  set connection timeout to 3 seconds.
- `gocurl --http1.1 -H "Host: virtual.test" -H "User-Agent:" http://127.0.0.1:8080/`
  connect to the URL address, send `virtual.test` as HTTP Host, and omit
  User-Agent. For HTTPS, the URL still determines TLS SNI unless
  `--tls-servername` is set separately.
- `gocurl --http1.1 --request-target='/wire%2Fpath?x=1' http://127.0.0.1:8080/routing-path`
  send the supplied HTTP/1.1 origin-form target while retaining the URL for
  connection routing. This override is unavailable for HTTP/2, HTTP/3, OHTTP,
  and plain HTTP requests through an HTTP proxy.
- `gocurl --http1.1 --no-default-headers -d 'payload' http://127.0.0.1:8080/upload`
  omit gocurl's User-Agent and automatic form Content-Type. HTTP/1.1 still
  requires Host and body framing; specify any other headers with `-H`.
  In this mode, a supplied `Content-Length` must match a known body length;
  `Transfer-Encoding: chunked` is supported when a body source is present. The
  two cannot be combined. Duplicate hop-by-hop fields, request trailers and
  target-side `Proxy-Authorization` are rejected before connecting. A streamed
  stdin body has unknown length, so use chunked framing instead of an explicit
  `Content-Length`.
- `gocurl --http2 --h2-header-table-size=8192 --h2-max-frame-size=32768 --h2-max-header-list-size=65536 https://example.com/`
  set the three supported HTTP/2 client SETTINGS. Flow-control windows remain
  controlled by the underlying transport; DATA payload size has a separate
  control below.
- `gocurl --http2 --h2-settings-order=MAX_FRAME_SIZE,ENABLE_PUSH --h2-pseudo-order=authority,method,path,scheme https://example.com/`
  reorder the first outbound SETTINGS frame and request pseudo-headers. The
  named SETTINGS IDs must actually be advertised by the transport; omitted IDs
  follow in their original order. Pseudo-header rewriting re-encodes HPACK and
  does not support CONNECT requests or request trailers. The two flags do not
  by themselves reproduce an arbitrary HTTP/2 fingerprint.
- `gocurl --http2 --h2-data-frame-size=1024 -d 'payload' https://example.com/`
  cap outbound DATA payloads at 1024 bytes per frame while preserving the
  request body and END_STREAM semantics. Other frame types and flow-control
  windows remain transport-controlled.
- `gocurl --http2 --h2-header-frame-size=1024 https://example.com/`
  split the first outbound request header block into HEADERS and CONTINUATION
  payloads of at most 1024 bytes. If no header-order override is requested,
  the original HPACK block is preserved; this does not control subsequent
  header blocks or all HTTP/2 framing.
- `gocurl --http2 --h2-frame-padding=16 -d payload https://example.com/`
  add 16 zero padding bytes to the first request HEADERS and every outbound
  DATA frame. Frame size limits include the padding overhead.
- `gocurl --http2 --h2-priority=0:16:false https://example.com/`
  send a PRIORITY frame for request stream 1 (dependency 0, weight 16,
  non-exclusive).
- `gocurl --http2 --h2-header-order=x-b,x-a -H 'X-A: first' -H 'X-A: second' -H 'X-B: value' https://example.com/`
  place the named regular HTTP/2 fields first, retaining repeated values;
  unlisted fields follow in transport order. This re-encodes the HPACK block
  and does not reproduce arbitrary HPACK bytes.
- `gocurl --http3 --h3-setting=0x40=127 https://example.com/`
  add an HTTP/3 extension SETTINGS entry. Repeat the flag for more entries.
  Standard/reserved setting IDs are rejected. SETTINGS ordering remains
  controlled by quic-go.
- `gocurl --http3 --h3-datagrams https://example.com/`
  advertise both standard HTTP/3 Datagrams SETTINGS and the matching QUIC
  datagram transport parameter; the peer must also support datagrams.
- `gocurl --http3 --quic-version=2 --quic-initial-stream-window=65536 --quic-initial-connection-window=262144 --quic-max-idle-timeout-ms=7000 --quic-max-incoming-streams=10 --quic-max-incoming-uni-streams=12 https://example.com/`
  set the supported QUIC version and transport parameters. A local server test
  verifies the received parameters and negotiated version. Parameter order has
  a separate control below; unconfigured fields and packetization remain
  library-owned. This is not a full QUIC fingerprint. TLS profile controls do
  not materialize custom uTLS ClientHello
  fields for QUIC.
- `gocurl --http3 --json-output https://example.com/`
  include the observed QUIC ClientHello fingerprint in the connection report.
  The report retains the last complete ClientHello, including an HRR follow-up;
  it does not mean the QUIC TLS
  ClientHello was built from a custom browser preset.
- `gocurl --http3 --quic-initial-packet-size=1300 https://example.com/`
  set the first QUIC Initial datagram size; the local qlog capture verifies
  the received datagram length.
- `gocurl --http3 --quic-connection-id-length=8 https://example.com/`
  set the client source connection ID length; a local server verifies the
  Initial packet on the wire. QUIC ClientHello remains generated by Go's TLS
  implementation and is reported separately when JSON output is enabled.
- `gocurl --http3 --quic-reset-stream-at https://example.com/`
  advertise quic-go's experimental `RESET_STREAM_AT` transport parameter.
  This is a draft extension, and peers that don't support it may reject it.
- `gocurl --http3 --quic-disable-active-migration https://example.com/`
  advertise QUIC's standard `disable_active_migration` transport parameter
  (ID `0x0c`); its presence can also be prioritized with the transport-parameter
  order option.
- `gocurl --http3 --quic-active-connection-id-limit=4 https://example.com/`
  advertise a peer limit of four active connection IDs (supported range 2..4).
  The local qlog test checks the value received by the server.
- `gocurl --http3 --quic-ack-delay-exponent=0 https://example.com/`
  advertise an explicit QUIC `ack_delay_exponent` (0..20); explicit zero is
  distinct from leaving the quic-go default unchanged.
- `gocurl --http3 --quic-max-ack-delay-ms=0 https://example.com/`
  advertise an explicit `max_ack_delay` value in whole milliseconds (0..16383).
- `gocurl --http3 --quic-max-udp-payload-size=1350 https://example.com/`
  advertise `max_udp_payload_size` (1200..1452 bytes for this transport).
- `gocurl --http3 --quic-initial-max-stream-data-bidi-local=111 --quic-initial-max-stream-data-bidi-remote=222 --quic-initial-max-stream-data-uni=333 https://example.com/`
  configure the three QUIC initial stream-data transport parameters separately;
  these override `--quic-initial-stream-window` for the corresponding types.
- `gocurl --http3 --quic-transport-parameter-order=0x4,0x1,0x5 https://example.com/`
  send `initial_max_data`, `max_idle_timeout`, and
  `initial_max_stream_data_bidi_local` first, in that order. QUIC grease stays
  first; unlisted parameters follow in quic-go's standard order.

<a id="newstuff"></a>

### New stuff

Also, you can use some new stuff that is not supported by curl.

- `gocurl --json-output https://httpbin.agrd.workers.dev/get` write output in
  machine-readable format (JSON), including prepared request details and TLS
  connection observations.
- `gocurl --json-output --json-redact-header Authorization https://example.test/`
  omits the Authorization value from JSON request metadata without changing the
  outgoing request.
- `gocurl --tls-split-hello 5:50 https://httpbin.agrd.workers.dev/get` split
  TLS ClientHello in two parts and make a 50ms delay after sending the first
  part.
- `gocurl --tls-random "gyufwmGYeIiq0B4nUjEYu3NcqVdlHbIXhx74fq4terc=" https://httpbin.agrd.workers.dev/get`
  use a custom TLS ClientHello random value.
- `gocurl -v --ech https://crypto.cloudflare.com/cdn-cgi/trace` enables support
  for ECH (Encrypted Client Hello) for the request. More on this [below](#ech).
- `gocurl --dns-servers "tls://dns.google" https://httpbin.agrd.workers.dev/get`
  uses custom DNS-over-TLS server to resolve hostnames. More on this
  [below](#dns).
- `gocurl --experiment pq https://pq.cloudflareresearch.com/` enables
  post-quantum cryptography support for the request. More on this [below](#pq).
- `gocurl wss://httpbin.agrd.workers.dev/ws` sends a WS upgrade request.
- `gocurl -d "test message" wss://httpbin.agrd.workers.dev/ws` establishes a WS
  connection, sends the first message through it and reads the response.

<a id="ech"></a>

#### Encrypted ClientHello

ECH or Encrypted Client Hello is a new standard that allows completely
encrypting TLS Client Hello. Currently, the RFC is in the [draft stage][echrfc],
but it is already supported by some big names [like Cloudflare][echcloudflare].
`gocurl` supports ECH and provides several options to use it.

The simple option is just add `--ech` flag and see what happens:

```shell
gocurl -v --ech https://crypto.cloudflare.com/cdn-cgi/trace
```

In this case, `gocurl` will try to discover the ECH configuration from DNS
records and then use them to establish the connection.

Instead of that, you may choose to supply your own configuration in the same
base64-encoded format as used by the SVCB record:

```shell
# Send a type=https query and find ech record there.
% dig -t https crypto.cloudflare.com. +short
1 . alpn="http/1.1,h2" ipv4hint=162.159.137.85,162.159.138.85 ech=AEX+DQBBvgAgACARWS42g5NmDZo5pIpTWSwHzTwzdRKPdUW732QbyUeyDQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7::a29f:8955,2606:4700:7::a29f:8a55

# You can now pass it to gocurl.
gocurl -v \
  --echconfig "AEX+DQBBvgAgACARWS42g5NmDZo5pIpTWSwHzTwzdRKPdUW732QbyUeyDQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" \
  https://crypto.cloudflare.com/cdn-cgi/trace
```

> Interesting thing about ECH is that it may connect even if you use an expired
> configuration (see HelloRetryRequest in the RFC). It depends on both the
> server and the client implementation and does not work with Cloudflare at the
> moment.

Here's what happens under the hood:

1. `gocurl` resolves `crypto.cloudflare.com` IP address and connects to it.
2. It sends TLS ClientHello (outer) with encrypted inner ClientHello to that IP
   address. The ServerName field in the outer ClientHello is set to the one that
   is encoded in the ECH configuration (in this example it will be
   `cloudflare-ech.com`), and in the inner encrypted ClientHello it will be
   set to `crypto.cloudflare.com`.

You may want to configure a specific "client-facing" server instead and the way
to do that is to use `--connect-to`. Let's send a request to `cloudflare.com`
and use `crypto.cloudflare.com` as a client-facing server for that.

```shell
gocurl -v \
  --connect-to "cloudflare.com:443:crypto.cloudflare.com:443" \
  --echconfig "AEX+DQBBvgAgACARWS42g5NmDZo5pIpTWSwHzTwzdRKPdUW732QbyUeyDQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" \
  https://cloudflare.com/cdn-cgi/trace
```

> For this command to work you may need to replace `--echconfig` with the
> current one discovered using DNS as was explained before.

Here's what happens now:

1. `gocurl` connects to `crypto.cloudflare.com` (client-facing relay).
2. Sends a TLS ClientHello with `cloudflare-ech.com` in the Server Name
   extension.
3. Establishes a TLS connection with `cloudflare.com` using the inner encrypted
   ClientHello.

[echrfc]: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/

[echcloudflare]: https://blog.cloudflare.com/handshake-encryption-endgame-an-ech-update/

<a id="dns"></a>

#### Custom DNS servers

`gocurl` allows using custom DNS servers to resolve hostnames when making
requests. This can be achieved by using `--dns-servers` command-line argument.
`curl` with `c-ares` also supports this command-line argument, but `gocurl`
adds encrypted DNS support on top of it, it supports all popular DNS encryption
protocols: DNS-over-QUIC, DNS-over-HTTPS, DNS-over-TLS and DNSCrypt.

You can specify multiple DNS servers, in this case `gocurl` will attempt to use
them one by one until it receives a response or until all of them fail:

```shell
gocurl \
  --dns-servers "tls://dns.adguard-dns.com,tls://dns.google" \
  https://example.org/

```

- DNS-over-QUIC

  ```shell
  gocurl --dns-servers "quic://dns.adguard-dns.com" https://example.org/
  ```

- DNS-over-HTTPS

  ```shell
  gocurl --dns-servers "https://dns.adguard-dns.com/dns-query" https://example.org/
  ```

- DNS-over-TLS

  ```shell
  gocurl --dns-servers "tls://dns.adguard-dns.com" https://example.org/
  ```

- DNSCrypt

  ```shell
  gocurl \
      --dns-servers sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20 \
      https://example.org/
  ```

<a id="ohttp"></a>

#### Oblivious HTTP

[Oblivious HTTP (OHTTP)][ohttp] is an IETF standard protocol that provides
end-to-end encryption for HTTP requests and responses while hiding the client's
identity from the target server. It works by routing encrypted requests through
a relay and gateway, ensuring that:

- The **relay** sees who is making requests but not what is being requested.
- The **gateway** sees what is being requested but not who is making the request.
- The **target server** receives a normal HTTP request from the gateway.

This separation provides strong privacy guarantees, making OHTTP useful for
privacy-sensitive applications.

`gocurl` has built-in support for OHTTP and can send requests through any
OHTTP gateway by specifying two command-line arguments:

- `--ohttp-gateway-url` - URL of the OHTTP gateway where the encrypted request
  will be sent.
- `--ohttp-keys-url` - URL from which to retrieve the OHTTP KeyConfig needed to
  encrypt the request.

Here's how to make an OHTTP request to `httpbin.agrd.workers.dev` using a demo
gateway:

```shell
gocurl -v \
  --ohttp-gateway-url "https://httpbin.agrd.workers.dev/ohttp/gateway" \
  --ohttp-keys-url "https://httpbin.agrd.workers.dev/ohttp/config" \
  https://httpbin.agrd.workers.dev/get
```

This command will:

1. Download the OHTTP KeyConfig from the keys URL.
2. Encrypt your request to `https://httpbin.agrd.workers.dev/get` using OHTTP.
3. Send the encrypted request to the gateway.
4. Receive the encrypted response from the gateway.
5. Decrypt and display the response.

You can also make POST requests through OHTTP:

```shell
gocurl -v \
  --ohttp-gateway-url "https://httpbin.agrd.workers.dev/ohttp/gateway" \
  --ohttp-keys-url "https://httpbin.agrd.workers.dev/ohttp/config" \
  -d "test data" \
  https://httpbin.agrd.workers.dev/post
```

One more example that uses a demo gateway from [Oblivious Network][ohttpdemo]:

```shell
gocurl -v \
  --ohttp-gateway-url "https://demo-gateway.oblivious.network/gateway" \
  --ohttp-keys-url "https://demo-gateway.oblivious.network/ohttp-configs" \
  https://httpbin.agrd.workers.dev/get
```

[ohttp]: https://www.ietf.org/rfc/rfc9458.html

[ohttpdemo]: https://docs.oblivious.network/docs/quickstart/

<a id="websocket"></a>

#### WebSocket support

`gocurl` provides some initial support for WebSocket protocol. It may be
extended in the future, see the corresponding [Github issue][wsissue].

- `gocurl wss://httpbin.agrd.workers.dev/ws` sends a WS upgrade request.
- `gocurl -d "test message" wss://httpbin.agrd.workers.dev/ws` establishes a WS
  connection, sends the first message through it and reads the response.

[wsissue]: https://github.com/ameshkov/gocurl/issues/17

<a id="exp"></a>

#### Experimental flags

Experimental flags are added to `gocurl` whenever there's a feature that may be
completely changed or removed in the future. Experiments can be enabled using
the `--experiment=<name[:value]>` argument where `name` is the experiment name
and `value` is an optional string value (the need for it depends on the actual
experiment).

<a id="pq"></a>

##### Post-quantum cryptography

Post-quantum (PQ) cryptography has been designed to be secure against the
threat of quantum computers. You can learn more about it from Cloudflare's
[blog post][postquantum]. `gocurl` supports it via the `--experiment=pq` flag.

Note, that it is not available for `--http3` at the moment.

```shell
gocurl --experiment pq https://pq.cloudflareresearch.com/
```

[postquantum]: https://blog.cloudflare.com/post-quantum-for-all/

<a id="development"></a>

## Go API

The versioned `github.com/ameshkov/gocurl/pkg/gocurl` package can send requests
without invoking the CLI. It shares request validation, TLS profile handling,
and transports with gocurl. Close the result after consuming the response body:

```go
result, err := gocurl.Do(ctx, gocurl.Request{
    URL:         "https://example.test/",
    HTTPVersion: "1.1",
    Headers: []gocurl.Header{
        {Name: "X-First", Value: "one"},
        {Name: "X-Second", Value: "two"},
    },
})
if err != nil {
    return err
}
defer result.Close()
defer io.Copy(io.Discard, result.Response.Body)
```

`Request.Body` accepts any `io.Reader`, including binary data. For a non-nil
body, set `ContentLength` to a positive exact byte count when known; zero or a
negative value means unknown length. HTTP/1.1 sends unknown-length bodies using
chunked transfer encoding. The reader is consumed once: gocurl does not
automatically follow redirects or retry by replaying it.

For WebSocket, use a `ws://` or `wss://` URL; the API creates the HTTP/1.1
upgrade handshake. A valid `101 Switching Protocols` response has its
`Sec-WebSocket-Accept` proof checked before `Do` returns. The returned response
body is a full-duplex `io.ReadWriteCloser`; it exposes the upgraded byte stream,
not a message-level WebSocket API, so callers are responsible for framing,
masking client frames, and handling control frames.

`Request.Headers` is an ordered slice, not a map. With HTTP/1.1, header order,
repeated fields, and supplied name casing are preserved on the wire; HTTP/2
applies its protocol-required lowercase field names. For example, two `Header`
entries named `X-Tag` are sent as two fields in their configured positions.
`Request{HTTPVersion: "1.1", NoDefaultHeaders: true}` suppresses gocurl's
default `User-Agent` and form `Content-Type`; explicit `Headers` remain intact.
Call `result.RequestMetadata()` for a detached, JSON-friendly request snapshot.
`JSONRedactHeaders` masks matching values in that snapshot without changing the
request sent on the wire or `Response.Request`. The body is not included.
Marshalling `Result.Response.Request` directly is not redacted; use the snapshot
when serializing request metadata that may contain secrets.

Use `TLSProfile{ProfilePath: "profile.json", Check: true}` to request a TLS
profile check. `Result.TLSReports` contains the observed per-connection report.
The Go API can also build a profile directly from a supported uTLS preset:
`TLSProfile{ClientHello: &TLSClientHello{Preset: "chrome-120", ALPN: []string{"http/1.1"}, CipherSuites: []uint16{0x1301, 0x1302, 0x1303}}}`.
`TLSClientHello` also accepts a server-name override, supported TLS versions,
groups, signature algorithms, and extension order. Unspecified fields inherit
the preset; direct profiles are validated before dialing and cannot be combined
with an imported profile or imported-profile check policy.
`Request{TLSServerName: "sni.example.test"}` overrides target TLS SNI without
changing the URL or HTTP `Host`; for a manual ClientHello, set
`TLSProfile.ClientHello.ServerName` instead (conflicting SNI values are rejected).
`Request{TLSMinVersion: "1.2", TLSMaxVersion: "1.3"}` applies the same
minimum/maximum TLS version bounds as `--tlsv1.2` and `--tls-max`. The accepted
values are `"1.2"` and `"1.3"`; a minimum of 1.3 with a maximum of 1.2 is
rejected. `TLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}`
maps to `--ciphers`; consistent with Go's TLS config, this list affects TLS
1.0–1.2 cipher suites, not TLS 1.3 suites. These overrides cannot be combined
with a manually materialized `TLSProfile.ClientHello`.
`Request{PostQuantum: true}` enables the experimental hybrid
`X25519MLKEM768` group (`--experiment=pq`) for supported TCP TLS requests. It
cannot be combined with a manual `TLSProfile.ClientHello` and is rejected for
plain HTTP and HTTP/3, where this TLS implementation is not available. The zero
value leaves the existing TLS behavior unchanged.
`Request{ConnectTimeout: 3*time.Second}` sets the same connection timeout as
`--connect-timeout 3` (including DNS/ECH discovery, TCP/SOCKS connection setup,
HTTP CONNECT, HTTPS-proxy TLS, and the target TLS/QUIC handshake). Once the handshake completes, this timer
does not limit response headers or body reads. Use zero to retain existing defaults; nonzero durations must be
whole seconds. This timeout does not replace the request context deadline,
which can bound the complete request separately.
Cancellation closes sockets during plain DNS and proxy setup and interrupts
ClientHello split delays. Legacy encrypted DNS upstreams lack a contextual
exchange: cancellation returns control immediately, but the library worker
can finish later under its own timeouts. The configured five-second upstream
timeout is not a guaranteed total bound across bootstrap, TLS setup, and retries.
For Oblivious HTTP, set both `Request.OHTTPGatewayURL` and
`Request.OHTTPKeysURL`, for example:
`Request{OHTTPGatewayURL: "https://gateway.example/ohttp", OHTTPKeysURL: "https://gateway.example/keys"}`.
The request's URL, method, headers, and body describe the encrypted inner
request; the gateway and keys URLs describe the outer network requests.

The Go request API also exposes the CLI's ECH controls:
`Request{ECH: true}` discovers an ECH configuration through DNS HTTPS/SVCB,
`Request{ECHConfig: "<base64 ECHConfigList>"}` supplies one explicitly and
implicitly enables ECH, and `Request{ECHGrease: true}` sends an ECH GREASE
extension without config discovery. ECH GREASE is not a negotiated ECH session.
`Request{TLSRandom: randomBytes}` overrides the ClientHello random and requires
exactly 32 bytes; leaving it nil preserves the default random generation.
`Request{ProxyURL: "https://proxy.example.test:8443", ProxyInsecure: true}`
disables certificate verification for the HTTPS proxy only; `Insecure` controls
verification of the target TLS connection independently.
`Request{Resolve: map[string][]string{"example.test": {"192.0.2.10", "2001:db8::10"}}}`
pins the hostname to the listed IPv4/IPv6 addresses. The `"*"` key applies an
address list to all hosts; as with the CLI option, the port is ignored.
`Request{IPVersion: "4"}` or `IPVersion: "6"` restricts DNS lookups to A or
AAAA records, matching `--ipv4`/`--ipv6`; an empty value keeps normal dual-stack
lookup behavior. `Request{DNSServers: []string{"127.0.0.1:5353",
"tls://dns.example.test"}}` selects the same plain or encrypted DNS upstream
formats accepted by `--dns-servers`. These settings affect hostname resolution;
they do not rewrite literal IP addresses in the URL.
`Request{ConnectTo: []string{"example.test:443:127.0.0.1:8443"}}` redirects
matching socket connections using the same mapping syntax as `--connect-to`;
the URL, HTTP `Host`, and TLS SNI remain based on the original hostname.
`Request{TLSSplitHello: &TLSSplitHello{FirstChunkSize: 5, Delay: 50*time.Millisecond}}`
splits the ClientHello after five bytes and delays the remainder by 50 ms; the
delay must use whole-millisecond precision. Keep the first chunk smaller than
the encoded ClientHello record.

### Request field contract

The complete [API/CLI parity matrix](docs/API_CLI_PARITY.md) includes every
top-level and nested public request field, independent CLI configuration
comparisons, actual local wire/e2e evidence, and applicable negative boundaries.

The table below lists every top-level `Request` field, its CLI equivalent (or
why there is none), and the zero/nil behavior and principal constraints.
Field-level test names are maintained in the adjacent Go API test files;
wire-level behavior is called out in the regression column where a dedicated
local test exists.

| Go API field | CLI mapping | Zero/nil behavior and constraints | Regression test |
| --- | --- | --- | --- |
| `Request.URL` | Positional `<URL>` | Required; empty is rejected before transport creation. | `TestClientDoRejectsMissingURLBeforeNetwork` |
| `Request.Method` | `--request` / `-X` | Empty keeps GET; otherwise becomes the HTTP method. | `TestClientDoPreservesKnownAndUnknownBinaryBodyLengths` |
| `Request.TLSServerName` | `--tls-servername` | Empty derives SNI from URL; does not change URL or Host; conflicting manual-profile SNI is rejected. | `TestClientDoOverridesTLSServerNameWithoutChangingHTTPHost`; `TestClientDoConnectToRedirectsSocketWithoutChangingHostOrSNI` |
| `Request.TLSMinVersion` | `--tlsv1.2` / `--tlsv1.3` | Empty keeps default; values are `1.2` or `1.3`; cannot exceed maximum. | `TestClientDoEnforcesTLSVersionBounds` |
| `Request.TLSMaxVersion` | `--tls-max` | Empty keeps default; values are `1.2` or `1.3`; cannot be below minimum. | `TestClientDoEnforcesTLSVersionBounds` |
| `Request.TLSCipherSuites` | `--ciphers` | Empty keeps defaults; names cannot be empty or contain whitespace; affects TLS 1.0–1.2, not TLS 1.3; conflicts with manual ClientHello. | `TestRequestArgsTLSVersionAndCipherSettingsMatchCLIConfig`; `TestClientDoTLSCipherSuitesOnWire` |
| `Request.PostQuantum` | `--experiment=pq` | False keeps default; true requires HTTPS/TCP TLS, conflicts with manual ClientHello and HTTP/3. | `TestClientDoPostQuantumHandshakeAcrossProxyRoutes` |
| `Request.RequestTarget` | `--request-target` | Empty uses URL target; overrides only HTTP/1.1 origin-form; unsupported for WebSocket, OHTTP, HTTP/2 and HTTP/3. | `TestClientDoRequestTargetOverridesWireTargetOnly` |
| `Request.NoDefaultHeaders` | `--no-default-headers` | False keeps defaults; true requires HTTP/1.1 and is unsupported for WebSocket/OHTTP; explicit headers remain. | `TestClientDoNoDefaultHeadersKeepsOnlyExplicitHeaders` |
| `Request.JSONRedactHeaders` | Repeat `--json-redact-header` | Nil/empty redacts nothing; masks only `RequestMetadata`, not wire headers or `Response.Request`. | `TestResultRequestMetadataRedactsDetachedHeaderSnapshot` |
| `Request.Headers` | Repeat `--header` | Nil/empty adds none; slice order and repeated names are retained where protocol permits. | `TestClientDoPreservesOrderedRepeatedHeadersOnHTTP11Wire` |
| `Request.Body` | Go API only; CLI has `--data` / `--data-binary` | Nil sends no body; a supplied reader is consumed once and is not replayed for redirects/retries. | `TestClientDoStreamingBodyFailureDoesNotRetry` |
| `Request.ContentLength` | Go API only; CLI derives it from body source | Positive means exact byte count; zero/negative means unknown for a non-nil body. | `TestClientDoPreservesKnownAndUnknownBinaryBodyLengths` |
| `Request.ProxyURL` | `--proxy` / `-x` | Empty is direct; scheme selects the proxy transport and its compatibility rules. | `TestClientDoWSSAcrossDirectAndProxyRoutes` |
| `Request.ProxyInsecure` | `--proxy-insecure` | False verifies HTTPS-proxy certificate; true skips proxy verification only, not target verification. | `TestClientDoWSSAcrossDirectAndProxyRoutes` |
| `Request.ConnectTimeout` | `--connect-timeout` | Zero keeps default; otherwise must be a non-negative whole number of seconds; request context remains separate. | `TestRequestArgsConnectTimeoutMatchesCLIConfig`; `TestClientDoConnectTimeoutBoundsHTTPSProxyTLSHandshake` |
| `Request.ConnectTo` | Repeat `--connect-to` | Nil/empty leaves dialing unchanged; socket destination changes while URL, Host and SNI retain original host. | `TestClientDoConnectToRedirectsSocketWithoutChangingHostOrSNI` |
| `Request.Resolve` | Repeat `--resolve` | Nil/empty uses normal DNS; each entry needs a host and at least one valid IP; `*` applies globally. | `TestClientDoResolvePinsHostnameToLocalTLSServer` |
| `Request.IPVersion` | `--ipv4` / `--ipv6` | Empty leaves dual-stack selection; accepted values are `4` and `6`. | `TestRequestArgsDNSControlsMatchCLIConfig`; `TestClientDoUsesCustomDNSUpstreamAndIPv4Only`; `TestClientDoUsesCustomDNSUpstreamAndIPv6Only` |
| `Request.DNSServers` | `--dns-servers` | Nil/empty uses system defaults; entries must be non-empty DNS upstream addresses. | `TestRequestArgsDNSControlsMatchCLIConfig`; `TestClientDoUsesCustomDNSUpstreamAndIPv4Only`; `TestClientDoUsesCustomDNSUpstreamAndIPv6Only` |
| `Request.ProxyHTTP2Connect` | `--proxy-http2-connect` | False uses normal CONNECT; true requires HTTPS proxy with h2 ALPN and is incompatible with HTTP/3. | `TestClientDoHTTP2ThroughHTTPSProxyConnect` |
| `Request.HTTPVersion` | `--http1.1` / `--http2` / `--http3` | Empty negotiates by default; accepted explicit values are `1.1`, `2`, `3`. | `TestClientDoHTTP2AgainstLocalTLSServer`; `TestClientDoHTTP3AgainstLocalQUICServer` |
| `Request.HTTP2Settings` | `--h2-header-table-size`, `--h2-max-frame-size`, `--h2-max-header-list-size` | Zero members keep defaults; nonzero members are range-checked and require HTTP/2. | `TestHTTP2SettingsOnWire`; `TestClientDoHTTP2SettingsAndOrderOnWire` |
| `Request.HTTP2PseudoOrder` | `--h2-pseudo-order` | Nil/empty keeps protocol default; names/order are validated and require HTTP/2. | `TestHTTP2PseudoHeaderOrderOnWire`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP2SettingsOrder` | `--h2-settings-order` | Nil/empty keeps default; supplied IDs are validated and require HTTP/2. | `TestRequestArgsHTTPSettings`; `TestClientDoHTTP2SettingsAndOrderOnWire` |
| `Request.HTTP2DataFrameSize` | `--h2-data-frame-size` | Zero keeps default; valid range is 1–16384 bytes and requires HTTP/2. | `TestHTTP2DataFrameSizeOnWire`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP2HeaderFrameSize` | `--h2-header-frame-size` | Zero keeps default; nonzero value is validated and requires HTTP/2. | `TestHTTP2HeaderFrameSizeWithoutHeaderRewriteGetsResponse`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP2FramePadding` | `--h2-frame-padding` | Zero disables configured padding; nonzero adds zero padding and requires HTTP/2. | `TestParseHTTP2FramePadding`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP2HeaderOrder` | `--h2-header-order` | Nil/empty keeps transport order; listed headers are prioritized; requires HTTP/2. | `TestParseHTTP2HeaderOrder`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP2Priority` | `--h2-priority` | Nil omits PRIORITY; weight must be 1–256; requires HTTP/2. | `TestHTTP2PriorityFrameOnWire`; `TestClientDoHTTP2FrameControlsOnWire` |
| `Request.HTTP3AdditionalSettings` | Repeat `--h3-setting` | Nil/empty adds none; extension IDs are validated; explicit zero values are retained; requires HTTP/3. | `TestHTTP3AdditionalSettingsOnWire`; `TestClientDoHTTP3SettingsOnWire` |
| `Request.HTTP3Datagrams` | `--h3-datagrams` | False disables datagrams; true enables HTTP/3 datagram negotiation. | `TestHTTP3AdditionalSettingsOnWire`; `TestClientDoHTTP3SettingsOnWire` |
| `Request.QUICTransport` | Applicable `--quic-*` options | Zero/nil members keep defaults; pointer fields may explicitly set zero where supported; ranges are validated; requires HTTP/3. | `TestQUICTransportParametersOnWire`; `TestClientDoQUICTransportParametersOnWire` |
| `Request.QUICTransportParameterOrder` | `--quic-transport-parameter-order` | Nil/empty keeps default order; supplied IDs are validated and prioritized; requires HTTP/3. | `TestQUICTransportParametersOnWire`; `TestClientDoQUICTransportParameterOrderOnWire` |
| `Request.Insecure` | `--insecure` / `-k` | False verifies target certificates; true skips target verification only. | `TestClientDoWSSAcrossDirectAndProxyRoutes` |
| `Request.ECH` | `--ech` | False disables ECH; true discovers a config through DNS HTTPS/SVCB unless explicit config is supplied. | `TestClientDoECHAcceptedAcrossProxyRoutes` |
| `Request.ECHGrease` | `--echgrease` | False disables GREASE; true sends GREASE without discovery and does not mean ECH was accepted. | `TestClientDoECHGreaseReportsUnobservedHandshake` |
| `Request.ECHConfig` | `--echconfig` | Empty uses discovery behavior; non-empty base64 ECHConfigList implicitly enables ECH. | `TestClientDoECHAcceptedAcrossProxyRoutes` |
| `Request.OHTTPGatewayURL` | `--ohttp-gateway-url` | Must be set with `OHTTPKeysURL`; defines the outer gateway request. | `TestClientDoOHTTPThroughHTTPAndSOCKSProxies` |
| `Request.OHTTPKeysURL` | `--ohttp-keys-url` | Must be set with `OHTTPGatewayURL`; same-origin endpoints can reuse one HTTP/1.1 TLS connection. | `TestClientDoOHTTPThroughHTTPAndSOCKSProxies` |
| `Request.TLSRandom` | `--tls-random` | Nil uses generated random; non-nil must contain exactly 32 bytes. | `TestRequestArgsTLSRandomMatchesCLIConfig`; `TestClientDoTLSRandomOnWire` |
| `Request.TLSSplitHello` | `--tls-split-hello` | Nil disables splitting; chunk size must be positive and delay non-negative whole milliseconds. | `TestRequestArgsTLSSplitHelloMatchesCLIConfig`; `TestClientDoTLSSplitHelloOnWire` |
| `Request.TLSProfile` | TLS and proxy TLS profile flags | Nil imports none; imported and manual ClientHello profiles are exclusive; direct-profile check modes need imported expectations. | `TestClientDoManualTLSClientHelloFieldsOnWire`; `TestClientDoManualTLSClientHelloExtensionFieldsOnWire`; `TestClientDoHTTP11ThroughHTTPSProxyConnect`; `TestClientDoRejectsUnsupportedTLSProfileBeforeNetwork` |

The table's field coverage is checked against `Request` by
`TestRequestFieldContractTableCoversEveryField`. Detailed HTTP/2/HTTP/3 controls,
including each nested `HTTP2Settings` and `QUICTransport` member, remain listed
in the protocol-specific table below.

### HTTP framing controls

HTTP framing controls are available through the same Go `Request` API. They
map to the corresponding CLI options and are validated by the shared config
parser:

| Go API field | CLI option | Behavior and limits |
| --- | --- | --- |
| `Method` | `--request` / `-X` | Selects the HTTP method; an empty value keeps the default method. |
| `RequestTarget` | `--request-target` | Overrides only the HTTP/1.1 origin-form target; URL, Host, and connection destination stay unchanged. |
| `ProxyHTTP2Connect` | `--proxy-http2-connect` | Enables HTTP/2 CONNECT through an HTTPS proxy that negotiates `h2`. |
| `HTTP2Settings.HeaderTableSize` | `--h2-header-table-size` | Nonzero `SETTINGS_HEADER_TABLE_SIZE`; zero retains the default. |
| `HTTP2Settings.MaxFrameSize` | `--h2-max-frame-size` | Nonzero `SETTINGS_MAX_FRAME_SIZE` within the protocol range. |
| `HTTP2Settings.MaxHeaderListSize` | `--h2-max-header-list-size` | Nonzero `SETTINGS_MAX_HEADER_LIST_SIZE`; zero retains the default. |
| `HTTP2PseudoOrder` | `--h2-pseudo-order` | Pseudo-header order; use names `method`, `scheme`, `authority`, `path`. |
| `HTTP2SettingsOrder` | `--h2-settings-order` | Prioritizes named SETTINGS IDs in the first SETTINGS frame; remaining IDs retain their default order. |
| `HTTP2DataFrameSize` | `--h2-data-frame-size` | Maximum DATA payload per frame, 1–16384 bytes. |
| `HTTP2HeaderFrameSize` | `--h2-header-frame-size` | Maximum HEADERS/CONTINUATION payload size. |
| `HTTP2FramePadding` | `--h2-frame-padding` | Adds the configured zero padding to request HEADERS and DATA frames. |
| `HTTP2HeaderOrder` | `--h2-header-order` | Prioritizes listed regular headers; unlisted headers follow transport order. |
| `HTTP2Priority` | `--h2-priority` | Emits a PRIORITY frame with dependency, weight (1–256), and exclusivity. |
| `HTTP3AdditionalSettings` | `--h3-setting` | Adds extension setting IDs; values may be zero and are emitted in ascending ID order. |
| `HTTP3Datagrams` | `--h3-datagrams` | Negotiates HTTP/3 datagram support. |
| `QUICTransport` | `--quic-*` options | Configures the documented QUIC transport-parameter subset; zero/nil generally keeps the library default, while pointer fields can explicitly set zero where supported. |
| `QUICTransportParameterOrder` | `--quic-transport-parameter-order` | Lists transport-parameter IDs to emit first; omitted IDs retain the implementation's default order. |

Set `HTTPVersion` to `"2"` or `"3"` when using protocol-specific fields. The
HTTP/2 and HTTP/3 wire behavior, defaults, and unsupported controls are detailed
in [the extension specification](docs/JA3PROXY_EXTENSION_TZ.md); CLI options
remain the reference for validation ranges and compatibility rules.

## Development

The HTTP/3 fingerprint controls depend on a small vendored `quic-go` patch.
Its upstream base, exact changed-file inventory, supported behavior, and
upgrade checks are documented in
[`docs/VENDORED_QUIC_PATCH.md`](docs/VENDORED_QUIC_PATCH.md).

To set up this repository for development, clone it and run:

```shell
make init
```

`make init` installs a git **pre-commit** hook to
`.git/hooks/pre-commit`. On every commit the hook:

1. Checks the staged content for temporary todo markers (`FIXME` and `TODO!!`)
   and blocks the commit if any are found. Note that documentation files (like
   `README.md`) are exempt from this check, since they may legitimately
   mention those markers.
2. Runs `make check`, the same quality gate as CI, which runs linters and
   tests.

The hook is stored in [`.githooks/pre-commit`](./.githooks/pre-commit) so you
can review exactly what it does. Re-run `make init` to re-install it after
pulling changes.

Requirements:

- [Go](https://go.dev/) (see `go.mod` for the required version).
- [golangci-lint](https://golangci-lint.run/).
- [markdownlint-cli](https://github.com/igorshubovych/markdownlint-cli) (run
  via `npx`, needs Node.js).
- `make` and `git`.

Useful commands:

- `make lint` — run `markdownlint-cli` and `golangci-lint`.
- `make test` — run the test suite.
- `make check` — run `make lint` and `make test` in sequence.
- `make build` — build the `gocurl` binary.

For Windows without `make`, run `powershell -File .\scripts\check.ps1`.
The script selects an installed Go with the same major/minor version as
`go.mod`, checks the linter's build toolchain, and runs module verification,
Markdown lint, Go lint, vet, race tests with benchmarks, vendored QUIC tests,
and build. It stops on the first failure and restores PATH and GOTOOLCHAIN.
Use `-GoExecutable` and `-LintExecutable` to specify executable paths.
Do not mix a newer Go toolchain with a linter built with an older Go: the
linters may crash instead of reporting code issues.

<a id="allcmdarguments"></a>

## All command-line arguments

```shell
Usage:
  gocurl [OPTIONS]

Application Options:
      --url=<URL>                                           URL the request will be made to. Can be specified without
                                                            any flags.
  -X, --request=<method>                                    HTTP method. GET by default.
      --request-target=</path?query>                         Override the HTTP/1.1 origin-form request target without
                                                            changing the connection URL.
      --no-default-headers                                  Do not add gocurl User-Agent or form Content-Type; requires
                                                            --http1.1.
  -d, --data=<data>                                         Sends the specified data to the HTTP server using content
                                                            type application/x-www-form-urlencoded.
      --data-binary=<source>                                Sends binary data from @<file> or @- (standard input)
                                                            without form encoding.
  -H, --header=                                             Extra header to include in the request. Can be specified
                                                            multiple times.
      --header-file=<file>                                  Read additional headers from a UTF-8 file (one Name: value
                                                            per line); applied before --header options.
  -x, --proxy=[protocol://username:password@]host[:port]    Use the specified proxy. The proxy string can be specified
                                                            with a protocol:// prefix.
      --proxy-insecure                                      Disable TLS certificate verification for an HTTPS proxy only.
      --connect-to=<HOST1:PORT1:HOST2:PORT2>                For a request to the given HOST1:PORT1 pair, connect to
                                                            HOST2:PORT2 instead. Can be specified multiple times.
      --connect-timeout=<seconds>                           Maximum time in seconds allowed for the connection phase.
  -I, --head                                                Fetch the headers only.
  -k, --insecure                                            Disables TLS verification of the connection.
      --tlsv1.3                                             Forces gocurl to use TLS v1.3 or newer.
      --tlsv1.2                                             Forces gocurl to use TLS v1.2 or newer.
      --tls-max=<VERSION>                                   (TLS) VERSION defines maximum supported TLS version. Can be
                                                            1.2 or 1.3. The minimum acceptable version is set by
                                                            tlsv1.2 or tlsv1.3.
      --ciphers=<space-separated list of ciphers>           Specifies which ciphers to use in the connection, see
                                                            https://go.dev/src/crypto/tls/cipher_suites.go for the full
                                                            list of available ciphers.
      --tls-servername=<HOSTNAME>                           Specifies the server name that will be sent in TLS
                                                            ClientHello
      --tls-profile=<file>                                  Import a JA3Proxy TLS ClientHello profile JSON file.
      --tls-profile-check                                   Compare the ClientHello observed on the wire with the
                                                            imported TLS profile.
      --tls-profile-strict                                  Fail if the TLS profile check is partial, unsupported, or
                                                            mismatched; implies --tls-profile-check.
      --proxy-tls-profile=<file>                            Import a separate TLS ClientHello profile for an HTTPS
                                                            proxy.
      --proxy-http2-connect                                 Use HTTP/2 CONNECT through an HTTPS proxy (requires proxy
                                                            ALPN h2).
      --proxy-tls-profile-check                             Compare the HTTPS-proxy ClientHello with
                                                            --proxy-tls-profile.
      --proxy-tls-profile-strict                            Fail if the HTTPS-proxy profile check is partial,
                                                            unsupported, or mismatched; implies
                                                            --proxy-tls-profile-check.
      --http1.1                                             Forces gocurl to use HTTP v1.1.
      --http2                                               Forces gocurl to use HTTP v2.
      --http3                                               Forces gocurl to use HTTP v3.
      --h2-header-table-size=<bytes>                        HTTP/2 SETTINGS_HEADER_TABLE_SIZE (nonzero).
      --h2-max-frame-size=<bytes>                           HTTP/2 SETTINGS_MAX_FRAME_SIZE (16384..16777215).
      --h2-max-header-list-size=<bytes>                     HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE (nonzero).
      --h2-pseudo-order=<names>                             HTTP/2 request pseudo-header order, e.g.
                                                            method,scheme,authority,path; requires --http2.
      --h2-settings-order=<names>                           Order advertised HTTP/2 SETTINGS IDs, e.g.
                                                            ENABLE_PUSH,INITIAL_WINDOW_SIZE,MAX_FRAME_SIZE; requires
                                                            --http2.
      --h2-data-frame-size=<bytes>                          Maximum outbound HTTP/2 DATA payload per frame (1..16384);
                                                            requires --http2.
      --h2-header-frame-size=<bytes>                        Maximum outbound request HEADERS/CONTINUATION payload per
                                                            frame (1..16384); requires --http2.
      --h2-frame-padding=<bytes>                            Padding bytes (1..255) on the first request HEADERS and
                                                            outbound DATA frames; requires --http2.
      --h2-header-order=<names>                             HTTP/2 regular header-name order; listed fields first,
                                                            others retain transport order.
      --h2-priority=<dependency:weight:exclusive>           Send HTTP/2 PRIORITY for the request stream:
                                                            dependency:weight:exclusive (weight 1..256); requires
                                                            --http2.
      --h3-setting=<id=value>                               Additional HTTP/3 SETTINGS ID=VALUE (decimal or 0x hex);
                                                            repeatable.
      --h3-datagrams                                        Enable HTTP/3 Datagrams and advertise QUIC datagram support;
                                                            requires --http3.
      --quic-initial-stream-window=<bytes>                  QUIC initial stream receive window for HTTP/3.
      --quic-initial-max-stream-data-bidi-local=<bytes>      QUIC initial_max_stream_data_bidi_local (0..2^62-1);
                                                            overrides --quic-initial-stream-window.
      --quic-initial-max-stream-data-bidi-remote=<bytes>     QUIC initial_max_stream_data_bidi_remote (0..2^62-1);
                                                            overrides --quic-initial-stream-window.
      --quic-initial-max-stream-data-uni=<bytes>             QUIC initial_max_stream_data_uni (0..2^62-1); overrides
                                                            --quic-initial-stream-window.
      --quic-initial-connection-window=<bytes>              QUIC initial connection receive window for HTTP/3.
      --quic-max-idle-timeout-ms=<milliseconds>             QUIC maximum idle timeout advertised by the HTTP/3 client.
      --quic-max-incoming-streams=<count>                   Maximum peer-initiated bidirectional QUIC streams for HTTP/3.
      --quic-max-incoming-uni-streams=<count>               Maximum peer-initiated unidirectional QUIC streams for
                                                            HTTP/3 (at least 3).
      --quic-version=<1|2>                                  Force QUIC version 1 or 2 for HTTP/3.
      --quic-initial-packet-size=<bytes>                    Initial QUIC packet size in bytes (1200..1452) for HTTP/3.
      --quic-connection-id-length=<bytes>                   Client QUIC source connection ID length (1..20) for HTTP/3.
      --quic-active-connection-id-limit=<count>             QUIC active_connection_id_limit transport parameter
                                                            (2..4 supported by this transport) for HTTP/3.
      --quic-ack-delay-exponent=<exponent>                  QUIC ack_delay_exponent (0..20) for HTTP/3.
      --quic-max-ack-delay-ms=<milliseconds>                QUIC max_ack_delay transport parameter in milliseconds
                                                            (0..16383) for HTTP/3.
      --quic-max-udp-payload-size=<bytes>                   QUIC max_udp_payload_size (1200..1452 bytes supported by
                                                            this transport) for HTTP/3.
      --quic-reset-stream-at                                Advertise the experimental QUIC RESET_STREAM_AT extension; requires --http3.
      --quic-transport-parameter-order=<ids>                 Order client QUIC transport parameter IDs (decimal or 0x hex); requires --http3.
      --quic-disable-active-migration                     Advertise the QUIC disable_active_migration transport
                                                          parameter; requires --http3.
      --ech                                                 Enables ECH support for the request.
      --echgrease                                           Forces sending ECH grease in the ClientHello, but does not
                                                            try to resolve the ECH configuration.
      --echconfig=<base64-encoded data>                     ECH configuration to use for this request. Implicitly
                                                            enables --ech when specified.
  -4, --ipv4                                                This option tells gocurl to use IPv4 addresses only when
                                                            resolving host names.
  -6, --ipv6                                                This option tells gocurl to use IPv6 addresses only when
                                                            resolving host names.
      --dns-servers=<DNSADDR1,DNSADDR2>                     DNS servers to use when making the request. Supports
                                                            encrypted DNS: tls://, https://, quic://, sdns://
      --resolve=<[+]host:port:addr[,addr]...>               Provide a custom address for a specific host. port is
                                                            ignored by gocurl. '*' can be used instead of the host
                                                            name. Can be specified multiple times.
      --tls-split-hello=<CHUNKSIZE:DELAY>                   An option that allows splitting TLS ClientHello in two
                                                            parts in order to avoid common DPI systems detecting TLS.
                                                            CHUNKSIZE is the size of the first bytes before ClientHello
                                                            is split, DELAY is delay in milliseconds before sending the
                                                            second part.
      --tls-random=<base64>                                 Base64-encoded 32-byte TLS ClientHello random value.
      --json-output                                         Makes gocurl write machine-readable output in JSON format.
      --json-redact-header=<name>                            Redact this request header from JSON metadata; can be specified multiple times.
  -o, --output=<file>                                       Defines where to write the received data. If not set,
                                                            gocurl will write everything to stdout.
      --experiment=<name[:value]>                           Allows enabling experimental options. See the documentation
                                                            for available options. Can be specified multiple times.
      --ohttp-gateway-url=<URL>                             URL of the Oblivious HTTP gateway where the request should
                                                            be sent.
      --ohttp-keys-url=<URL>                                URL from which to retrieve Oblivious HTTP KeyConfig to use
                                                            for encrypting the request.
  -v, --verbose                                             Verbose output (optional).

Help Options:
  -h, --help                                                Show this help message
```
