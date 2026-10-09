// Package config is responsible for parsing and validating cmd arguments.
package config

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AdguardTeam/dnsproxy/upstream"
	ctls "github.com/ameshkov/cfcrypto/tls"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"golang.org/x/net/http/httpguts"
)

// DNSExchangeTimeout bounds DNS library operations without caller contexts.
const DNSExchangeTimeout = 5 * time.Second

// Config is a strictly-typed and validated configuration structure which is
// created from Options (command-line arguments).
type Config struct {
	// RequestURL is the URL where the target request will be sent.
	RequestURL *url.URL

	// Method is the HTTP method of the request.
	Method string

	// RequestTarget overrides the HTTP/1.1 origin-form target on the wire.
	RequestTarget string

	// NoDefaultHeaders omits gocurl's automatic User-Agent and form Content-Type.
	NoDefaultHeaders bool

	// Head signals that the tool should only fetch headers. If specified,
	// headers will be written to the output.
	Head bool

	// Data specifies the data to be sent to the HTTP server.
	Data string

	// DataBinary identifies a binary body source in @<file> or @- form.
	DataBinary string

	// Headers is the HTTP headers that will be added to the request.
	Headers http.Header

	// OrderedHeaders retains input order and original field-name casing.
	// Header-file entries precede command-line -H entries.
	OrderedHeaders []string

	// ProxyURL is a URL of a proxy to use with this connection.
	ProxyURL *url.URL

	// ProxyHTTP2Connect enables HTTP/2 CONNECT to an HTTPS proxy.
	ProxyHTTP2Connect bool

	// ProxyInsecure disables certificate verification only for an HTTPS proxy.
	ProxyInsecure bool

	// ConnectTo is a mapping of "host1:port1" to "host2:port2" pairs that
	// allows retargeting the connection.
	ConnectTo map[string]string

	// Insecure disables TLS verification of the connection.
	Insecure bool

	// TLSMinVersion is a minimum supported TLS version.
	TLSMinVersion uint16

	// TLSMaxVersion is a maximum supported TLS version.
	TLSMaxVersion uint16

	// TLSCiphers is a list of ciphers that the client will send in the TLS
	// ClientHello.
	TLSCiphers []uint16

	// TLSServerName allows to send a specified server name in the TLS
	// ClientHello extension.
	TLSServerName string

	// TLSProfile selects a prevalidated uTLS ClientHello profile for HTTPS.
	TLSProfile *utlsengine.Profile

	// TLSProfileDocument contains the imported expectations used by profile checking.
	TLSProfileDocument *utlsengine.ClientProfile

	// TLSProfileCheck compares the captured on-wire ClientHello to the profile.
	TLSProfileCheck bool

	// TLSProfileStrict makes any non-MATCH result fail the request.
	TLSProfileStrict bool

	// TLSProfileUnsupported records profile fields the current uTLS adapter ignores.
	TLSProfileUnsupported []string

	// ProxyTLSProfile selects an independent uTLS profile for the TLS connection to an HTTPS proxy.
	ProxyTLSProfile *utlsengine.Profile

	// ProxyTLSProfileDocument contains the expectations for HTTPS-proxy TLS checks.
	ProxyTLSProfileDocument *utlsengine.ClientProfile

	// ProxyTLSProfileCheck compares the HTTPS-proxy ClientHello against its imported profile.
	ProxyTLSProfileCheck bool

	// ProxyTLSProfileStrict makes any non-MATCH HTTPS-proxy result fail the request.
	ProxyTLSProfileStrict bool

	// ProxyTLSProfileUnsupported records optional fields the proxy uTLS adapter ignores.
	ProxyTLSProfileUnsupported []string

	// ForceHTTP11 forces using HTTP/1.1.
	ForceHTTP11 bool

	// ForceHTTP2 forces using HTTP/2.
	ForceHTTP2 bool

	// ForceHTTP3 forces using HTTP/3.
	ForceHTTP3 bool

	// HTTP2Settings configures the supported outbound HTTP/2 SETTINGS values.
	HTTP2Settings HTTP2Settings

	// HTTP2PseudoOrder rewrites the first request HEADERS block on the wire.
	HTTP2PseudoOrder []string

	// HTTP2SettingsOrder reorders the first client SETTINGS frame on the wire.
	HTTP2SettingsOrder []uint16

	// HTTP2DataFrameSize caps outbound DATA frame payloads when nonzero.
	HTTP2DataFrameSize uint32

	// HTTP2HeaderFrameSize caps outbound HEADERS/CONTINUATION payloads when nonzero.
	HTTP2HeaderFrameSize uint32

	// HTTP2FramePadding adds this many zero padding bytes to request HEADERS and DATA.
	HTTP2FramePadding uint8

	// HTTP2HeaderOrder prioritizes named regular headers in the first request block.
	HTTP2HeaderOrder []string

	// HTTP2Priority configures a PRIORITY frame for the first request stream.
	HTTP2Priority *HTTP2Priority

	// HTTP3AdditionalSettings contains extension settings, not standard HTTP/3 settings.
	HTTP3AdditionalSettings map[uint64]uint64

	// HTTP3Datagrams enables HTTP/3 and QUIC datagram negotiation.
	HTTP3Datagrams bool

	// QUICTransport controls the supported HTTP/3 QUIC transport parameters.
	QUICTransport QUICTransport

	// QUICTransportParameterOrder places listed client transport parameter IDs
	// first; remaining parameters keep quic-go's default order.
	QUICTransportParameterOrder []uint64

	// ECH forces usage of Encrypted Client Hello for the request.  If other
	// ECH-related fields are not specified, the ECH configuration will be
	// received from the DNS settings.
	ECH bool

	// ECHGrease forces sending ECH grease in the ClientHello.  This option
	// does not try to resolve the ECH configuration and is only used for
	// testing ECH grease.
	ECHGrease bool

	// ECHConfigs is a set of ECH configurations that will be used when opening
	// an encrypted connection.
	ECHConfigs []ctls.ECHConfig

	// Resolve is a map of host:ips pairs.  It allows specifying custom IP
	// addresses for a specific host or all hosts (if '*' is used instead of
	// the host name).
	Resolve map[string][]net.IP

	// IPv4 if configured forces usage of IP4 addresses only when doing DNS
	// resolution.
	IPv4 bool

	// IPv6 if configured forces usage of IP4 addresses only when doing DNS
	// resolution.
	IPv6 bool

	// DNSServers is a list of upstream DNS servers that will be used for
	// resolving hostnames.
	DNSServers []upstream.Upstream

	// TLSSplitChunkSize is a size of the first chunk of ClientHello that is
	// sent to the server.
	TLSSplitChunkSize int

	// TLSSplitDelay is a delay in milliseconds before sending the second
	// chunk of ClientHello.
	TLSSplitDelay int

	// TLSRandom is a 32-byte value to override the TLS ClientHello random.
	// If nil, use default.
	TLSRandom []byte

	// OutputJSON enables writing output in JSON format.
	OutputJSON bool

	// JSONRedactHeaders contains case-insensitive request header names redacted in JSON output.
	JSONRedactHeaders []string

	// OutputPath defines where to write the received data. If not set, the
	// received data will be written to stdout.
	OutputPath string

	// ConnectTimeout limits the maximum time in seconds allowed for the
	// connection phase. Applied to SOCKS5 proxy connections as well.
	ConnectTimeout int

	// Experiments is a map where the key is Experiment and value is its
	// optional configuration.
	Experiments map[Experiment]string

	// OHTTPGatewayURL is the URL of the Oblivious HTTP gateway where the
	// request should be sent.
	OHTTPGatewayURL *url.URL

	// OHTTPKeysURL is the URL from which to retrieve Oblivious HTTP KeyConfig
	// to use for encrypting the request.
	OHTTPKeysURL *url.URL

	// Verbose defines whether we should write the DEBUG-level log or not.
	Verbose bool

	// RawOptions is the raw command-line arguments struct (for logging only).
	RawOptions *Options
}

// Experiment is an enumeration of experimental features available for us via
// the --experiment flag.
type Experiment string

const (
	// ExpNone is just an empty value, not an experiment.
	ExpNone Experiment = ""

	// ExpPostQuantum stands for post-quantum cryptography.  See the website for
	// more details: https://pq.cloudflareresearch.com/.
	ExpPostQuantum Experiment = "pq"
)

// NewExperiment tries to create an Experiment from string.  Returns error if
// the string is not a valid member of the enumeration.
func NewExperiment(str string) (e Experiment, err error) {
	switch str {
	case string(ExpPostQuantum):
		return ExpPostQuantum, nil
	}

	return ExpNone, fmt.Errorf("invalid experiment name: %s", str)
}

// ParseConfig parses and validates the provided args and returns the final *Config
// object.
//
// Disable gocyclo for ParseConfig as it's supposed to be a large function with
// if conditions.
//
// nolint:gocyclo
func ParseConfig(args []string) (cfg *Config, err error) {
	opts, err := parseOptions(args)
	if err != nil {
		return nil, err
	}

	cfg = &Config{
		Method:            opts.Method,
		RequestTarget:     opts.RequestTarget,
		ProxyHTTP2Connect: opts.ProxyHTTP2Connect,
		ProxyInsecure:     opts.ProxyInsecure,
		NoDefaultHeaders:  opts.NoDefaultHeaders,
		Head:              opts.Head,
		Insecure:          opts.Insecure,
		Data:              opts.Data,
		DataBinary:        opts.DataBinary,
		OutputJSON:        opts.OutputJSON,
		JSONRedactHeaders: append([]string(nil), opts.JSONRedactHeaders...),
		OutputPath:        opts.OutputPath,
		ConnectTimeout:    opts.ConnectTimeout,
		Verbose:           opts.Verbose,
		ForceHTTP11:       opts.HTTPv11,
		ForceHTTP2:        opts.HTTPv2,
		ForceHTTP3:        opts.HTTPv3,
		HTTP3Datagrams:    opts.H3Datagrams,
		ECH:               opts.ECH,
		ECHGrease:         opts.ECHGrease,
		IPv4:              opts.IPv4,
		IPv6:              opts.IPv6,
		TLSServerName:     opts.TLSServerName,
		TLSProfileCheck:   opts.TLSProfileCheck || opts.TLSProfileStrict,
		TLSProfileStrict:  opts.TLSProfileStrict,
		RawOptions:        opts,
	}
	for i, name := range cfg.JSONRedactHeaders {
		name = strings.TrimSpace(name)
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("--json-redact-header has invalid header name %q", name)
		}
		cfg.JSONRedactHeaders[i] = name
	}

	cfg.RequestURL, err = url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL specified %s: %w", opts.URL, err)
	}

	if cfg.RequestURL.Scheme == "" {
		// Use http scheme by default.
		cfg.RequestURL.Scheme = "http"
	}
	if (cfg.RequestURL.Scheme == "ws" || cfg.RequestURL.Scheme == "wss") &&
		(cfg.ForceHTTP2 || cfg.ForceHTTP3) {
		return nil, fmt.Errorf("WebSocket requests require HTTP/1.1; --http2 and --http3 are unsupported")
	}
	if opts.DataBinary != "" {
		if opts.Data != "" {
			return nil, fmt.Errorf("--data and --data-binary cannot be used together")
		}
		if !strings.HasPrefix(opts.DataBinary, "@") || len(opts.DataBinary) == 1 {
			return nil, fmt.Errorf("--data-binary requires @<file> or @- for standard input")
		}
		if cfg.RequestURL.Scheme == "ws" || cfg.RequestURL.Scheme == "wss" {
			return nil, fmt.Errorf("--data-binary is not supported for WebSocket requests")
		}
	}

	if opts.ProxyURL != "" {
		cfg.ProxyURL, err = url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL specified %s: %w", opts.ProxyURL, err)
		}
	}
	if cfg.ForceHTTP3 && cfg.ProxyURL != nil &&
		(cfg.ProxyURL.Scheme == "http" || cfg.ProxyURL.Scheme == "https") {
		return nil, fmt.Errorf("--http3 does not support HTTP(S) proxies; use SOCKS5/SOCKS5H for UDP proxying")
	}
	if cfg.ProxyHTTP2Connect {
		if cfg.ProxyURL == nil || cfg.ProxyURL.Scheme != "https" {
			return nil, fmt.Errorf("--proxy-http2-connect requires an https:// --proxy")
		}
		if cfg.ForceHTTP3 {
			return nil, fmt.Errorf("--proxy-http2-connect cannot be used with --http3")
		}
	}
	if cfg.ProxyInsecure && (cfg.ProxyURL == nil || cfg.ProxyURL.Scheme != "https") {
		return nil, fmt.Errorf("--proxy-insecure requires an https:// --proxy")
	}
	if cfg.RequestTarget != "" {
		if !cfg.ForceHTTP11 || !strings.HasPrefix(cfg.RequestTarget, "/") ||
			strings.ContainsRune(cfg.RequestTarget, '#') || strings.IndexFunc(cfg.RequestTarget, func(r rune) bool {
			return r <= ' ' || r == 0x7f
		}) >= 0 {
			return nil, fmt.Errorf(
				"--request-target requires --http1.1 and an origin-form /path?query without spaces or control characters",
			)
		}
		if cfg.RequestURL.Scheme == "ws" || cfg.RequestURL.Scheme == "wss" {
			return nil, fmt.Errorf("--request-target is unsupported for WebSocket requests")
		}
		if cfg.OHTTPGatewayURL != nil || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("--request-target is incompatible with OHTTP")
		}
		if cfg.ProxyURL != nil && cfg.RequestURL.Scheme == "http" &&
			(cfg.ProxyURL.Scheme == "" || cfg.ProxyURL.Scheme == "http" || cfg.ProxyURL.Scheme == "https") {
			return nil, fmt.Errorf("--request-target is unsupported for plain HTTP requests through an HTTP proxy")
		}
	}
	if cfg.NoDefaultHeaders && !cfg.ForceHTTP11 {
		return nil, fmt.Errorf("--no-default-headers requires --http1.1")
	}
	if cfg.NoDefaultHeaders && (cfg.RequestURL.Scheme == "ws" || cfg.RequestURL.Scheme == "wss" ||
		opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "") {
		return nil, fmt.Errorf("--no-default-headers is unsupported for WebSocket and OHTTP requests")
	}
	if opts.H2HeaderTableSize != "" || opts.H2MaxFrameSize != "" || opts.H2MaxHeaderListSize != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("HTTP/2 SETTINGS options require --http2 without OHTTP")
		}
		cfg.HTTP2Settings, err = parseHTTP2Settings(
			opts.H2HeaderTableSize,
			opts.H2MaxFrameSize,
			opts.H2MaxHeaderListSize,
		)
		if err != nil {
			return nil, err
		}
	}
	if opts.H2PseudoOrder != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" ||
			strings.EqualFold(cfg.Method, http.MethodConnect) {
			return nil, fmt.Errorf("--h2-pseudo-order requires --http2 without OHTTP or CONNECT")
		}
		cfg.HTTP2PseudoOrder, err = parseHTTP2PseudoOrder(opts.H2PseudoOrder)
		if err != nil {
			return nil, err
		}
	}
	if opts.H2SettingsOrder != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("--h2-settings-order requires --http2 without OHTTP")
		}
		cfg.HTTP2SettingsOrder, err = parseHTTP2SettingsOrder(opts.H2SettingsOrder)
		if err != nil {
			return nil, err
		}
	}
	if opts.H2DataFrameSize != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("--h2-data-frame-size requires --http2 without OHTTP")
		}
		value, parseErr := strconv.ParseUint(opts.H2DataFrameSize, 10, 32)
		if parseErr != nil || value < 1 || value > 16384 {
			return nil, fmt.Errorf("--h2-data-frame-size must be 1..16384")
		}
		cfg.HTTP2DataFrameSize = uint32(value)
	}
	if opts.H2HeaderFrameSize != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" ||
			strings.EqualFold(cfg.Method, http.MethodConnect) {
			return nil, fmt.Errorf("--h2-header-frame-size requires --http2 without OHTTP or CONNECT")
		}
		value, parseErr := strconv.ParseUint(opts.H2HeaderFrameSize, 10, 32)
		if parseErr != nil || value < 1 || value > 16384 {
			return nil, fmt.Errorf("--h2-header-frame-size must be 1..16384")
		}
		cfg.HTTP2HeaderFrameSize = uint32(value)
	}
	if opts.H2FramePadding != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" ||
			strings.EqualFold(cfg.Method, http.MethodConnect) {
			return nil, fmt.Errorf("--h2-frame-padding requires --http2 without OHTTP or CONNECT")
		}
		value, parseErr := strconv.ParseUint(opts.H2FramePadding, 10, 8)
		if parseErr != nil || value == 0 {
			return nil, fmt.Errorf("--h2-frame-padding must be 1..255")
		}
		cfg.HTTP2FramePadding = uint8(value)
	}
	if cfg.HTTP2HeaderFrameSize != 0 && cfg.HTTP2FramePadding != 0 &&
		cfg.HTTP2HeaderFrameSize <= uint32(cfg.HTTP2FramePadding)+1 {
		return nil, fmt.Errorf("--h2-header-frame-size must exceed the --h2-frame-padding overhead")
	}
	if opts.H2HeaderOrder != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" ||
			strings.EqualFold(cfg.Method, http.MethodConnect) {
			return nil, fmt.Errorf("--h2-header-order requires --http2 without OHTTP or CONNECT")
		}
		cfg.HTTP2HeaderOrder, err = parseHTTP2HeaderOrder(opts.H2HeaderOrder)
		if err != nil {
			return nil, err
		}
	}
	if opts.H2Priority != "" {
		if !cfg.ForceHTTP2 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" ||
			strings.EqualFold(cfg.Method, http.MethodConnect) {
			return nil, fmt.Errorf("--h2-priority requires --http2 without OHTTP or CONNECT")
		}
		cfg.HTTP2Priority, err = parseHTTP2Priority(opts.H2Priority)
		if err != nil {
			return nil, err
		}
	}
	if len(opts.H3AdditionalSettings) != 0 {
		if !cfg.ForceHTTP3 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("--h3-setting requires --http3 without OHTTP")
		}
		cfg.HTTP3AdditionalSettings, err = parseHTTP3AdditionalSettings(opts.H3AdditionalSettings)
		if err != nil {
			return nil, err
		}
	}
	if cfg.HTTP3Datagrams && (!cfg.ForceHTTP3 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "") {
		return nil, fmt.Errorf("--h3-datagrams requires --http3 without OHTTP")
	}
	if opts.QUICInitialStreamWindow != "" ||
		opts.QUICInitialMaxStreamDataBidiLocal != "" ||
		opts.QUICInitialMaxStreamDataBidiRemote != "" ||
		opts.QUICInitialMaxStreamDataUni != "" ||
		opts.QUICInitialConnectionWindow != "" ||
		opts.QUICMaxIdleTimeoutMS != "" ||
		opts.QUICMaxIncomingStreams != "" ||
		opts.QUICMaxIncomingUniStreams != "" ||
		opts.QUICVersion != "" ||
		opts.QUICInitialPacketSize != "" ||
		opts.QUICConnectionIDLength != "" ||
		opts.QUICActiveConnectionIDLimit != "" ||
		opts.QUICAckDelayExponent != "" ||
		opts.QUICMaxAckDelayMS != "" ||
		opts.QUICMaxUDPPayloadSize != "" ||
		opts.QUICResetStreamAt ||
		opts.QUICDisableActiveMigration ||
		opts.QUICTransportParameterOrder != "" {
		if !cfg.ForceHTTP3 || opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
			return nil, fmt.Errorf("QUIC transport options require --http3 without OHTTP")
		}
		cfg.QUICTransport, err = parseQUICTransport(opts)
		if err != nil {
			return nil, err
		}
		cfg.QUICTransportParameterOrder, err = parseQUICTransportParameterOrder(opts.QUICTransportParameterOrder)
		if err != nil {
			return nil, err
		}
	}

	if len(opts.ConnectTo) > 0 {
		cfg.ConnectTo, err = parseConnectTo(opts.ConnectTo)
		if err != nil {
			return nil, fmt.Errorf("invalid connect-to specified %v: %w", opts.ConnectTo, err)
		}
	}

	if len(opts.Resolve) > 0 {
		cfg.Resolve, err = parseResolve(opts.Resolve)
		if err != nil {
			return nil, fmt.Errorf("invalid resolve specified %v: %w", opts.Resolve, err)
		}
	}

	if opts.DNSServers != "" {
		cfg.DNSServers, err = parseDNSServers(opts.DNSServers, opts.Insecure)
		if err != nil {
			return nil, fmt.Errorf("invalid dns-servers specified %s: %w", opts.DNSServers, err)
		}
	}

	orderedHeaders := make([]string, 0, len(opts.Headers))
	headerValues := make([]string, 0, len(opts.Headers))
	if opts.HeaderFile != "" {
		fileHeaders, readErr := readHeaderFile(opts.HeaderFile)
		if readErr != nil {
			return nil, readErr
		}
		orderedHeaders = append(orderedHeaders, fileHeaders...)
		headerValues = append(headerValues, fileHeaders...)
	}
	orderedHeaders = append(orderedHeaders, opts.Headers...)
	headerValues = append(headerValues, opts.Headers...)
	if len(orderedHeaders) > 0 {
		cfg.OrderedHeaders = append([]string(nil), orderedHeaders...)
		cfg.Headers, err = createHeaders(headerValues)
		if err != nil {
			return nil, err
		}
		if cfg.NoDefaultHeaders {
			if err := validateExactHeaders(cfg.Headers); err != nil {
				return nil, err
			}
		}
	}

	if opts.TLSv12 {
		cfg.TLSMinVersion = tls.VersionTLS12
	}

	if opts.TLSv13 {
		cfg.TLSMinVersion = tls.VersionTLS13
	}

	if opts.TLSMax == "1.2" {
		cfg.TLSMaxVersion = tls.VersionTLS12
	} else if opts.TLSMax == "1.3" {
		cfg.TLSMaxVersion = tls.VersionTLS13
	} else if opts.TLSMax != "" {
		return nil, fmt.Errorf("unsupported tls-max value: %s", opts.TLSMax)
	}

	if opts.TLSCiphers != "" {
		cipherNames := strings.Split(opts.TLSCiphers, " ")
		cfg.TLSCiphers = []uint16{}

		for _, cipherName := range cipherNames {
			cipher := getCipherSuiteByName(cipherName)

			if cipher == 0 {
				return nil, fmt.Errorf("cipher %s not found", cipherName)
			}

			cfg.TLSCiphers = append(cfg.TLSCiphers, cipher)
		}
	}

	if opts.TLSSplitHello != "" {
		cfg.TLSSplitChunkSize, cfg.TLSSplitDelay, err = parseTLSSplitHello(opts.TLSSplitHello)
		if err != nil {
			return nil, fmt.Errorf("invalid tls-split-hello: %w", err)
		}
	}

	if opts.TLSRandom != "" {
		var b []byte
		b, err = base64.StdEncoding.DecodeString(opts.TLSRandom)
		if err != nil {
			return nil, fmt.Errorf("--tls-random must be a valid base64 string: %w", err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("--tls-random must decode to exactly 32 bytes (got %d)", len(b))
		}
		cfg.TLSRandom = b
	}

	if opts.ECHConfig != "" {
		cfg.ECHConfigs, err = unmarshalECHConfigs(opts.ECHConfig)
		if err != nil {
			return nil, fmt.Errorf("invalid echconfig: %w", err)
		}

		// --echconfig implicitly enables --ech as well.
		cfg.ECH = true
	}

	if len(opts.Experiments) > 0 {
		cfg.Experiments, err = parseExperiments(opts.Experiments)
		if err != nil {
			return nil, fmt.Errorf("invalid experiments %v: %w", opts.Experiments, err)
		}
	}
	_, postQuantum := cfg.Experiments[ExpPostQuantum]
	if cfg.ForceHTTP3 && postQuantum {
		return nil, fmt.Errorf("--http3 cannot be combined with post-quantum TLS (--experiment=pq)")
	}

	// Parse and validate OHTTP options.
	if opts.OHTTPGatewayURL != "" || opts.OHTTPKeysURL != "" {
		// Both arguments must be specified together.
		if opts.OHTTPGatewayURL == "" || opts.OHTTPKeysURL == "" {
			return nil, fmt.Errorf("both --ohttp-gateway-url and --ohttp-keys-url must be specified")
		}

		cfg.OHTTPGatewayURL, err = url.Parse(opts.OHTTPGatewayURL)
		if err != nil {
			return nil, fmt.Errorf("invalid OHTTP gateway URL %s: %w", opts.OHTTPGatewayURL, err)
		}

		cfg.OHTTPKeysURL, err = url.Parse(opts.OHTTPKeysURL)
		if err != nil {
			return nil, fmt.Errorf("invalid OHTTP keys URL %s: %w", opts.OHTTPKeysURL, err)
		}
	}

	if (opts.TLSProfileCheck || opts.TLSProfileStrict) && opts.TLSProfile == "" {
		return nil, fmt.Errorf("--tls-profile-check and --tls-profile-strict require --tls-profile")
	}
	if (opts.ProxyTLSProfileCheck || opts.ProxyTLSProfileStrict) && opts.ProxyTLSProfile == "" {
		return nil, fmt.Errorf("--proxy-tls-profile-check and --proxy-tls-profile-strict require --proxy-tls-profile")
	}
	if opts.ProxyTLSProfile != "" {
		if cfg.ProxyURL == nil || cfg.ProxyURL.Scheme != "https" {
			return nil, fmt.Errorf("--proxy-tls-profile requires an https:// --proxy")
		}
		data, readErr := os.ReadFile(opts.ProxyTLSProfile)
		if readErr != nil {
			return nil, fmt.Errorf("read proxy TLS profile %q: %w", opts.ProxyTLSProfile, readErr)
		}
		profile, decodeErr := utlsengine.DecodeClientProfile(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		materialized, unsupported, materializeErr := profile.Materialize()
		if materializeErr != nil {
			return nil, materializeErr
		}
		if cfg.ProxyHTTP2Connect {
			if !containsALPN(materialized.ALPN, "h2") {
				return nil, fmt.Errorf("--proxy-tls-profile must offer h2 with --proxy-http2-connect")
			}
		} else if len(materialized.ALPN) != 1 || materialized.ALPN[0] != "http/1.1" {
			return nil, fmt.Errorf(
				"--proxy-tls-profile must offer only http/1.1 unless --proxy-http2-connect is enabled",
			)
		}
		cfg.ProxyTLSProfile = &materialized
		cfg.ProxyTLSProfileDocument = &profile
		cfg.ProxyTLSProfileCheck = opts.ProxyTLSProfileCheck || opts.ProxyTLSProfileStrict
		cfg.ProxyTLSProfileStrict = opts.ProxyTLSProfileStrict
		cfg.ProxyTLSProfileUnsupported = unsupported
	}

	if opts.TLSProfile != "" {
		if cfg.RequestURL.Scheme != "https" {
			return nil, fmt.Errorf("--tls-profile requires an https URL")
		}
		if opts.TLSv12 || opts.TLSv13 || opts.TLSMax != "" || opts.TLSCiphers != "" ||
			opts.TLSServerName != "" || opts.TLSRandom != "" || opts.ECH || opts.ECHGrease ||
			opts.ECHConfig != "" || opts.HTTPv3 || len(opts.OHTTPGatewayURL) > 0 ||
			postQuantum {
			return nil, fmt.Errorf(
				"--tls-profile cannot be combined with manual TLS settings, ECH, post-quantum TLS, HTTP/3, or OHTTP",
			)
		}
		data, readErr := os.ReadFile(opts.TLSProfile)
		if readErr != nil {
			return nil, fmt.Errorf("read TLS profile %q: %w", opts.TLSProfile, readErr)
		}
		profile, decodeErr := utlsengine.DecodeClientProfile(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		materialized, unsupported, materializeErr := profile.Materialize()
		if materializeErr != nil {
			return nil, materializeErr
		}
		if cfg.ForceHTTP11 && (len(materialized.ALPN) != 1 || materialized.ALPN[0] != "http/1.1") {
			return nil, fmt.Errorf("--tls-profile ALPN is incompatible with --http1.1")
		}
		if cfg.ForceHTTP2 && (len(materialized.ALPN) != 1 || materialized.ALPN[0] != "h2") {
			return nil, fmt.Errorf("--tls-profile ALPN is incompatible with --http2")
		}
		if !cfg.ForceHTTP2 && containsALPN(materialized.ALPN, "h2") {
			return nil, fmt.Errorf(
				"--tls-profile offering h2 requires --http2; automatic HTTP/2 negotiation is unavailable for uTLS connections",
			)
		}
		cfg.TLSProfile = &materialized
		cfg.TLSProfileDocument = &profile
		cfg.TLSProfileUnsupported = unsupported
	}

	return cfg, nil
}

func containsALPN(protocols []string, wanted string) bool {
	for _, protocol := range protocols {
		if protocol == wanted {
			return true
		}
	}
	return false
}

// getCipherSuiteByName tries to get the cipher suite by its name. Returns 0
// if no matching cipher found.
func getCipherSuiteByName(cipherName string) (cipher uint16) {
	for _, c := range tls.CipherSuites() {
		if c.Name == cipherName {
			return c.ID
		}
	}

	for _, c := range tls.InsecureCipherSuites() {
		if c.Name == cipherName {
			return c.ID
		}
	}

	return 0
}

// parseConnectTo creates a "connect-to" map from the string representation.
func parseConnectTo(connectTo []string) (m map[string]string, err error) {
	m = map[string]string{}
	for _, ct := range connectTo {
		parts := strings.SplitN(ct, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid connect-to format %s, expected HOST1:PORT1:HOST2:PORT2", ct)
		}

		oldHost := parts[0] + ":" + parts[1]
		newHost := parts[2] + ":" + parts[3]
		m[oldHost] = newHost
	}

	return m, nil
}

// parseResolve creates a "resolve" map from the string representation.
func parseResolve(resolve []string) (m map[string][]net.IP, err error) {
	m = map[string][]net.IP{}

	for _, r := range resolve {
		parts := strings.SplitN(r, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid resolve format %s, expected HOST:PORT:ADDRS", r)
		}

		host := parts[0]
		addrs := parts[2]
		var ipAddresses []net.IP

		for _, a := range strings.Split(addrs, ",") {
			ipAddr := net.ParseIP(a)
			if ipAddr == nil {
				return nil, fmt.Errorf("invalid addr %s", a)
			}

			// Trim zero bytes.
			if ipAddr.To4() != nil {
				ipAddr = ipAddr.To4()
			}

			ipAddresses = append(ipAddresses, ipAddr)
		}

		if len(ipAddresses) == 0 {
			return nil, fmt.Errorf("no addrs for %s", host)
		}

		m[host] = ipAddresses
	}

	return m, nil
}

// parseDNSServers parses --dns-servers command-line argument and returns the
// list of upstream.Upstream created from them.  If insecure is true and the
// upstreams use encrypted DNS, certificate verification will be disabled for
// them.
func parseDNSServers(dnsServers string, insecure bool) (upstreams []upstream.Upstream, err error) {
	addrs := strings.Split(dnsServers, ",")
	for _, addr := range addrs {
		opts := &upstream.Options{InsecureSkipVerify: insecure, Timeout: DNSExchangeTimeout}
		u, uErr := upstream.AddressToUpstream(addr, opts)
		if uErr != nil {
			return nil, fmt.Errorf("invalid DNS server %s: %w", addr, uErr)
		}

		upstreams = append(upstreams, u)
	}

	return upstreams, nil
}

// createHeaders creates HTTP headers map from the string array.
func createHeaders(headers []string) (h http.Header, err error) {
	h = http.Header{}

	for i, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 || !validHeaderFieldName(parts[0]) || strings.ContainsAny(parts[1], "\r\n\x00") {
			return nil, fmt.Errorf("invalid --header entry %d: expected a valid Name: value", i+1)
		}
		if strings.EqualFold(parts[0], "Host") {
			if len(h.Values("Host")) != 0 || strings.TrimSpace(parts[1]) == "" {
				return nil, fmt.Errorf("invalid --header entry %d: Host must have one non-empty value", i+1)
			}
		}
		h.Add(parts[0], parts[1])
	}

	return h, nil
}

// readHeaderFile reads and validates a UTF-8 header file. Empty lines are
// ignored; each non-empty line must contain one valid HTTP field.
func readHeaderFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read header file %q: %w", path, err)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("header file %q is not valid UTF-8", path)
	}

	lines := strings.Split(string(data), "\n")
	headers := make([]string, 0, len(lines))
	for i, line := range lines {
		lineNumber := i + 1
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, "\r\n") {
			return nil, fmt.Errorf("invalid header file line %d: embedded CR/LF", lineNumber)
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("invalid header file line %d: expected Name: value", lineNumber)
		}
		name, value := line[:colon], line[colon+1:]
		if !validHeaderFieldName(name) {
			return nil, fmt.Errorf("invalid header file line %d: invalid header name", lineNumber)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid header file line %d: invalid header value", lineNumber)
		}
		if strings.HasPrefix(value, " ") || strings.HasPrefix(value, "\t") {
			value = value[1:]
		}
		headers = append(headers, name+": "+value)
	}
	return headers, nil
}

func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// parseTLSSplitHello parses --tls-split-hello, returns error if it's invalid.
func parseTLSSplitHello(tlsSplitHello string) (chunkSize int, delay int, err error) {
	parts := strings.SplitN(tlsSplitHello, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid tls-split-hello format: %s", tlsSplitHello)
	}

	chunkSize, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid tls-split-hello: %w", err)
	}

	delay, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid tls-split-hello: %w", err)
	}

	return chunkSize, delay, nil
}

// unmarshalECHConfigs parses the base64-encoded ECH config.
func unmarshalECHConfigs(echConfig string) (echConfigs []ctls.ECHConfig, err error) {
	var b []byte
	b, err = base64.StdEncoding.DecodeString(echConfig)
	if err != nil {
		return nil, err
	}

	return ctls.UnmarshalECHConfigs(b)
}

// parseExperiments parses the --experiment command-line arguments into a map.
// Returns an error if the experiment name is invalid.
func parseExperiments(exps []string) (expMap map[Experiment]string, err error) {
	expMap = map[Experiment]string{}

	for _, exp := range exps {
		parts := strings.SplitN(exp, ":", 2)
		expName := parts[0]
		var value string
		if len(parts) == 2 {
			value = parts[1]
		}

		var e Experiment
		e, err = NewExperiment(expName)
		if err != nil {
			return nil, fmt.Errorf("invalid experiment: %s", exp)
		}

		expMap[e] = value
	}

	return expMap, nil
}
