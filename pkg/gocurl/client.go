// Package gocurl exposes the embeddable HTTP client API.
package gocurl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ameshkov/gocurl/internal/client"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/client/websocket"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
)

// APIVersion is the version of this Go API contract.
const APIVersion = "v1"

// Header is one ordered HTTP request header. Value is used verbatim; do not
// include the colon separator. Name casing and repetitions are retained when
// used with HTTP/1.1.
type Header struct {
	Name  string
	Value string
}

// TLSProfile selects the JA3Proxy ClientHello profile and comparison policy.
// ProfilePath and ProxyProfilePath refer to JSON profile files.
type TLSProfile struct {
	ProfilePath      string
	Check            bool
	Strict           bool
	ProxyProfilePath string
	ProxyCheck       bool
	ProxyStrict      bool
	// ClientHello selects a built-in uTLS preset and supported field overrides
	// instead of importing ProfilePath. Check/Strict require an imported profile.
	ClientHello *TLSClientHello
}

// TLSClientHello contains the supported, manually configurable ClientHello
// fields. Empty slices inherit the selected preset values.
type TLSClientHello struct {
	Preset              string
	ServerName          string
	CipherSuites        []uint16
	SupportedVersions   []uint16
	SupportedGroups     []uint16
	SignatureAlgorithms []uint16
	ExtensionOrder      []uint16
	ALPN                []string
}

// Request describes one outbound request. HTTPVersion accepts "1.1", "2",
// or "3"; an empty value uses the default negotiation behavior.
type Request struct {
	URL    string
	Method string
	// TLSServerName overrides the target TLS SNI without changing URL or HTTP Host.
	TLSServerName string
	// TLSMinVersion sets the minimum target TLS version ("1.2" or "1.3").
	TLSMinVersion string
	// TLSMaxVersion sets the maximum target TLS version ("1.2" or "1.3").
	TLSMaxVersion string
	// TLSCipherSuites selects target cipher-suite names as accepted by --ciphers.
	// As in Go's crypto/tls, this controls TLS 1.0–1.2 suites, not TLS 1.3 suites.
	TLSCipherSuites []string
	// PostQuantum enables the CLI's experimental hybrid X25519MLKEM768 TLS
	// group for supported TCP TLS connections. It is not available with HTTP/3.
	PostQuantum bool
	// RequestTarget overrides the HTTP/1.1 origin-form target without changing URL.
	RequestTarget string
	// NoDefaultHeaders disables gocurl's User-Agent and form Content-Type defaults.
	NoDefaultHeaders bool
	// JSONRedactHeaders hides these request header values in Result.RequestMetadata only.
	// It does not alter the outbound request or Response.Request.
	JSONRedactHeaders []string
	Headers           []Header
	Body              io.Reader
	// ContentLength is the exact body length when positive. Zero or negative
	// means unknown length for a non-nil body.
	ContentLength int64
	ProxyURL      string
	// ProxyInsecure disables certificate verification only for an HTTPS proxy.
	ProxyInsecure bool
	// ConnectTimeout limits the connection phase. Zero keeps the CLI default;
	// nonzero values must be whole seconds, matching --connect-timeout.
	ConnectTimeout time.Duration
	// ConnectTo redirects matching host:port dial targets using the CLI syntax
	// HOST1:PORT1:HOST2:PORT2. If a source host:port is repeated, the last entry
	// wins. URL, HTTP Host, and target TLS SNI continue to use the original host.
	ConnectTo []string
	// Resolve overrides DNS results for each hostname. Values are IP address
	// strings; an entry for "*" applies to all hosts. As in the CLI, port is
	// ignored by the underlying resolver.
	Resolve map[string][]string
	// IPVersion restricts hostname resolution to "4" (IPv4) or "6" (IPv6).
	// An empty value leaves address-family selection to the resolver.
	IPVersion string
	// DNSServers selects DNS upstreams using the same address syntax as
	// --dns-servers (including tls://, https://, quic://, and sdns:// forms).
	DNSServers []string
	// ProxyHTTP2Connect enables HTTP/2 CONNECT through an HTTPS proxy.
	ProxyHTTP2Connect bool
	HTTPVersion       string
	// HTTP2Settings controls supported HTTP/2 client SETTINGS (nonzero values).
	HTTP2Settings HTTP2Settings
	// HTTP2PseudoOrder contains method, scheme, authority, path in wire order.
	HTTP2PseudoOrder []string
	// HTTP2SettingsOrder prioritizes the named IDs in the initial SETTINGS frame.
	HTTP2SettingsOrder []string
	// HTTP2DataFrameSize caps outbound HTTP/2 DATA payloads per frame.
	HTTP2DataFrameSize uint32
	// HTTP2HeaderFrameSize caps outbound HEADERS/CONTINUATION payloads.
	HTTP2HeaderFrameSize uint32
	// HTTP2FramePadding adds zero padding bytes to request HEADERS and DATA frames.
	HTTP2FramePadding uint8
	// HTTP2HeaderOrder prioritizes the named regular HTTP/2 request headers.
	HTTP2HeaderOrder []string
	// HTTP2Priority requests an HTTP/2 PRIORITY frame for the request stream.
	HTTP2Priority *HTTP2Priority
	// HTTP3AdditionalSettings contains extension setting IDs and values.
	HTTP3AdditionalSettings map[uint64]uint64
	// HTTP3Datagrams negotiates standard HTTP/3 and QUIC datagram support.
	HTTP3Datagrams bool
	// QUICTransport configures supported HTTP/3 QUIC transport parameters.
	QUICTransport QUICTransport
	// QUICTransportParameterOrder lists client QUIC transport parameter IDs
	// to emit first; use decimal or protocol IDs as uint64 values.
	QUICTransportParameterOrder []uint64
	Insecure                    bool
	// ECH enables Encrypted ClientHello, discovering a config through DNS when
	// ECHConfig is empty.
	ECH bool
	// ECHGrease sends an ECH GREASE extension without resolving a server config.
	ECHGrease bool
	// ECHConfig is a base64-encoded ECHConfigList; it implicitly enables ECH.
	ECHConfig string
	// OHTTPGatewayURL is the URL receiving encapsulated Oblivious HTTP requests.
	// It must be set together with OHTTPKeysURL.
	OHTTPGatewayURL string
	// OHTTPKeysURL is the URL serving the OHTTP public KeyConfig. It must be
	// set together with OHTTPGatewayURL.
	OHTTPKeysURL string
	// TLSRandom overrides the 32-byte ClientHello random; nil uses the default.
	TLSRandom []byte
	// TLSSplitHello splits the ClientHello after FirstChunkSize bytes and waits
	// Delay before writing the remainder.
	TLSSplitHello *TLSSplitHello
	TLSProfile    *TLSProfile
}

// HTTP2Priority describes the request stream's dependency, weight (1..256), and exclusivity.
type HTTP2Priority struct {
	Dependency uint32
	Weight     uint16
	Exclusive  bool
}

// TLSSplitHello controls optional ClientHello record splitting.
type TLSSplitHello struct {
	FirstChunkSize int
	Delay          time.Duration
}

// Client is a stateless request client. Per-request TLS configuration is
// isolated; each Result owns the transport created for that request.
type Client struct{}

// HTTP2Settings mirrors the HTTP/2 wire settings exposed by the client.
type HTTP2Settings struct {
	HeaderTableSize   uint32
	MaxFrameSize      uint32
	MaxHeaderListSize uint32
}

// QUICTransport is the supported subset of QUIC transport parameters.
// Zero values use quic-go defaults.
type QUICTransport struct {
	InitialStreamReceiveWindow uint64
	// InitialMaxStreamDataBidiLocal controls initial_max_stream_data_bidi_local; nil uses the shared/default window.
	InitialMaxStreamDataBidiLocal *uint64
	// InitialMaxStreamDataBidiRemote controls initial_max_stream_data_bidi_remote; nil uses the shared/default window.
	InitialMaxStreamDataBidiRemote *uint64
	// InitialMaxStreamDataUni controls initial_max_stream_data_uni; nil uses the shared/default window.
	InitialMaxStreamDataUni        *uint64
	InitialConnectionReceiveWindow uint64
	MaxIdleTimeout                 time.Duration
	MaxIncomingStreams             int64
	MaxIncomingUniStreams          int64
	Version                        string
	InitialPacketSize              uint16
	ConnectionIDLength             int
	ActiveConnectionIDLimit        uint64
	// AckDelayExponent overrides QUIC ack_delay_exponent, including explicit zero.
	AckDelayExponent *uint8
	// MaxAckDelay overrides QUIC max_ack_delay, including explicit zero.
	MaxAckDelay *time.Duration
	// MaxUDPPayloadSize sets QUIC max_udp_payload_size (1200..1452); zero uses the default.
	MaxUDPPayloadSize   uint16
	EnableResetStreamAt bool
	// DisableActiveMigration advertises disable_active_migration to the peer.
	DisableActiveMigration bool
}

// NewClient creates a reusable, concurrency-safe API client.
func NewClient() *Client { return &Client{} }

// ConnectionReport describes a TLS connection observed for the request.
type ConnectionReport struct {
	ConnectionID         string                 `json:"connection_id"`
	Leg                  string                 `json:"leg"`
	Attempt              int                    `json:"attempt"`
	HelloIndex           int                    `json:"hello_index"`
	CaptureStatus        string                 `json:"capture_status"`
	Expected             TLSProfileExpectation  `json:"expected"`
	Actual               *TLSFingerprint        `json:"actual,omitempty"`
	Diff                 []TLSProfileDifference `json:"diff,omitempty"`
	Error                string                 `json:"error,omitempty"`
	EngineVersion        string                 `json:"engine_version,omitempty"`
	NormalizationVersion string                 `json:"normalization_version,omitempty"`
}

// TLSProfileExpectation contains expected fingerprint values from a profile.
type TLSProfileExpectation struct {
	JA3                  string `json:"ja3,omitempty"`
	JA3Hash              string `json:"ja3_hash,omitempty"`
	JA4                  string `json:"ja4,omitempty"`
	NormalizedSHA256     string `json:"normalized_sha256,omitempty"`
	NormalizationVersion string `json:"normalization_version,omitempty"`
	MaterializerVersion  string `json:"materializer_version,omitempty"`
	JA3Version           string `json:"ja3_version,omitempty"`
	JA4Version           string `json:"ja4_version,omitempty"`
}

// TLSFingerprint contains values calculated from the observed ClientHello.
type TLSFingerprint struct {
	JA3String            string   `json:"ja3_string"`
	JA3                  string   `json:"ja3_hash"`
	JA4                  string   `json:"ja4"`
	NormalizedSHA256     string   `json:"normalized_sha256"`
	NormalizationVersion string   `json:"normalization_version"`
	NormalizationError   string   `json:"normalization_error,omitempty"`
	CipherSuites         []uint16 `json:"cipher_suites"`
	ExtensionOrder       []uint16 `json:"extension_order"`
	ALPN                 []string `json:"alpn"`
	SupportedVersions    []uint16 `json:"supported_versions,omitempty"`
	SupportedGroups      []uint16 `json:"supported_groups,omitempty"`
	SignatureAlgorithms  []uint16 `json:"signature_algorithms,omitempty"`
}

// TLSProfileDifference is a path-specific expected/observed mismatch.
type TLSProfileDifference struct {
	Path     string `json:"path"`
	Expected any    `json:"expected"`
	Actual   any    `json:"actual"`
	Policy   string `json:"policy"`
}

// Result owns the response and its HTTP transport. Call Close after consuming
// the response body to release resources.
type Result struct {
	Response   *http.Response
	TLSReports []ConnectionReport
	transport  client.Transport
	metadata   requestMetadataOptions
}

// Close closes the response body and releases idle transport connections.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.Response != nil && r.Response.Body != nil {
		err = r.Response.Body.Close()
	}
	if r.transport != nil {
		if conn := r.transport.Conn(); conn != nil {
			_ = conn.Close()
		}
	}
	if closer, ok := r.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return err
}

// Do validates and sends one request using the same profile validation,
// transport, and TLS capture implementation as the gocurl CLI.
func Do(ctx context.Context, request Request) (*Result, error) {
	return NewClient().Do(ctx, request)
}

// Do validates and sends one request using this client.
func (c *Client) Do(ctx context.Context, request Request) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gocurl API: context is required")
	}
	args, err := requestArgs(request)
	if err != nil {
		return nil, err
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		return nil, fmt.Errorf("gocurl API: invalid request: %w", err)
	}
	if err = applyAPIManualTLSProfile(cfg, request); err != nil {
		return nil, err
	}
	cfg.OutputJSON = true // enable structured wire observations for Result.
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := client.NewTransport(cfg, out)
	if err != nil {
		return nil, fmt.Errorf("gocurl API: create transport: %w", err)
	}
	req, err := client.NewRequest(cfg)
	if err != nil {
		closeTransport(transport)
		return nil, fmt.Errorf("gocurl API: create request: %w", err)
	}
	req = req.WithContext(ctx)
	if request.Body != nil {
		if body, ok := request.Body.(io.ReadCloser); ok {
			req.Body = body
		} else {
			req.Body = io.NopCloser(request.Body)
		}
		if request.ContentLength > 0 {
			req.ContentLength = request.ContentLength
		} else {
			req.ContentLength = -1
		}
	}
	result, err := DoWithTransport(ctx, req, transport)
	if err != nil {
		closeTransport(transport)
		return nil, err
	}
	if websocket.IsWebSocket(cfg.RequestURL) && result.Response.StatusCode == http.StatusSwitchingProtocols &&
		!websocket.IsWebSocketResponse(result.Response) {
		_ = result.Response.Body.Close()
		closeTransport(transport)
		return nil, fmt.Errorf("gocurl API: invalid WebSocket handshake response")
	}
	result.transport = transport
	result.metadata = requestMetadataOptions{
		redactHeaders:         append([]string(nil), cfg.JSONRedactHeaders...),
		configuredHeaderOrder: append([]string(nil), cfg.OrderedHeaders...),
		requestTarget:         cfg.RequestTarget,
	}
	return result, nil
}

// DoWithTransport executes an already-built request through a caller-provided
// RoundTripper. The caller retains ownership of the RoundTripper; the returned
// Result owns only the response body. This entry point lets the CLI and Go API
// share response execution and TLS-report extraction while using the same
// validated transport configuration.
func DoWithTransport(ctx context.Context, req *http.Request, roundTripper http.RoundTripper) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gocurl API: context is required")
	}
	if req == nil {
		return nil, fmt.Errorf("gocurl API: request is required")
	}
	if roundTripper == nil {
		return nil, fmt.Errorf("gocurl API: RoundTripper is required")
	}
	req = req.WithContext(ctx)
	resp, err := roundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Request == nil {
		resp.Request = req
	}
	result := &Result{Response: resp}
	internalReports, _ := utlsengine.ProfileCheckReports(resp.Request.Context())
	for _, report := range internalReports {
		encoded, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("gocurl API: encode TLS report: %w", marshalErr)
		}
		var publicReport ConnectionReport
		if unmarshalErr := json.Unmarshal(encoded, &publicReport); unmarshalErr != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("gocurl API: decode TLS report: %w", unmarshalErr)
		}
		result.TLSReports = append(result.TLSReports, publicReport)
	}
	return result, nil
}

func closeTransport(transport client.Transport) {
	if transport == nil {
		return
	}
	if conn := transport.Conn(); conn != nil {
		_ = conn.Close()
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
