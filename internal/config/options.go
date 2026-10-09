package config

import (
	"encoding/json"
	"fmt"

	goFlags "github.com/jessevdk/go-flags"
)

// Options represents command-line arguments.
type Options struct {
	// URL represents the address the request will be made to. It is always the
	// last argument.
	URL string `long:"url" description:"URL the request will be made to. Can be specified without any flags." value-name:"<URL>"`

	// Method is the HTTP method to be used.
	Method string `short:"X" long:"request" description:"HTTP method. GET by default." value-name:"<method>"`

	// RequestTarget overrides the origin-form request target on HTTP/1.1 wire.
	RequestTarget string `long:"request-target" description:"Override the HTTP/1.1 origin-form request target without changing the connection URL." value-name:"</path?query>"`

	// NoDefaultHeaders omits gocurl's automatic User-Agent and form Content-Type.
	NoDefaultHeaders bool `long:"no-default-headers" description:"Do not add gocurl User-Agent or form Content-Type; requires --http1.1."`

	// Data specifies the data to be sent to the HTTP server.
	Data string `short:"d" long:"data" description:"Sends the specified data to the HTTP server using content type application/x-www-form-urlencoded." value-name:"<data>"`

	// DataBinary sends the exact bytes read from a file or standard input.
	DataBinary string `long:"data-binary" description:"Sends binary data from @<file> or @- (standard input) without form encoding." value-name:"<source>"`

	// Headers is an array of HTTP headers (format is "header: value") to
	// include in the request.
	Headers []string `short:"H" long:"header" description:"Extra header to include in the request. Can be specified multiple times."`

	// HeaderFile adds HTTP headers from a UTF-8 file before headers from -H.
	HeaderFile string `long:"header-file" description:"Read additional headers from a UTF-8 file (one Name: value per line); applied before --header options." value-name:"<file>"`

	// ProxyURL is a URL of a proxy to use with this connection.
	ProxyURL string `short:"x" long:"proxy" description:"Use the specified proxy. The proxy string can be specified with a protocol:// prefix." value-name:"[protocol://username:password@]host[:port]"`

	// ProxyHTTP2Connect enables HTTP/2 CONNECT for HTTPS proxies.
	ProxyHTTP2Connect bool `long:"proxy-http2-connect" description:"Use HTTP/2 CONNECT through an HTTPS proxy (requires proxy ALPN h2)."`

	// ProxyInsecure disables certificate verification only for an HTTPS proxy.
	ProxyInsecure bool `long:"proxy-insecure" description:"Disable TLS certificate verification for an HTTPS proxy only."`

	// ConnectTo allows to override the connection target, i.e. for a request
	// to the given HOST1:PORT1 pair, connect to HOST2:PORT2 instead.
	ConnectTo []string `long:"connect-to" description:"For a request to the given HOST1:PORT1 pair, connect to HOST2:PORT2 instead. Can be specified multiple times." value-name:"<HOST1:PORT1:HOST2:PORT2>"`

	// ConnectTimeout limits the maximum time in seconds allowed for the connection
	// phase. This is applied during proxy connections as well (e.g., SOCKS5).
	ConnectTimeout int `long:"connect-timeout" description:"Maximum time in seconds allowed for the connection phase." value-name:"<seconds>"`

	// Head signals that the tool should only fetch headers. If specified,
	// headers will be written to the output.
	Head bool `short:"I" long:"head" description:"Fetch the headers only." optional:"yes" optional-value:"true"`

	// Insecure disables TLS verification of the connection.
	Insecure bool `short:"k" long:"insecure" description:"Disables TLS verification of the connection." optional:"yes" optional-value:"true"`

	// TLSv13 forces to use TLS v1.3.
	TLSv13 bool `long:"tlsv1.3" description:"Forces gocurl to use TLS v1.3 or newer." optional:"yes" optional-value:"true"`

	// TLSv13 forces to use TLS v1.2.
	TLSv12 bool `long:"tlsv1.2" description:"Forces gocurl to use TLS v1.2 or newer." optional:"yes" optional-value:"true"`

	// TLSMax specifies the maximum supported TLS version.
	TLSMax string `long:"tls-max" description:"(TLS) VERSION defines maximum supported TLS version. Can be 1.2 or 1.3. The minimum acceptable version is set by tlsv1.2 or tlsv1.3." value-name:"<VERSION>"`

	// TLSCiphers specifies which ciphers to use in the connection, see
	// https://go.dev/src/crypto/tls/cipher_suites.go for the full list of
	// available ciphers.
	TLSCiphers string `long:"ciphers" description:"Specifies which ciphers to use in the connection, see https://go.dev/src/crypto/tls/cipher_suites.go for the full list of available ciphers." value-name:"<space-separated list of ciphers>"`

	// TLSServerName allows to send a specified server name in the TLS
	// ClientHello extension.
	TLSServerName string `long:"tls-servername" description:"Specifies the server name that will be sent in TLS ClientHello" value-name:"<HOSTNAME>"`

	// TLSProfile imports a JA3Proxy ClientHello profile for HTTPS requests.
	TLSProfile string `long:"tls-profile" description:"Import a JA3Proxy TLS ClientHello profile JSON file." value-name:"<file>"`

	// TLSProfileCheck reports the fingerprint observed on the wire and compares it with the profile.
	TLSProfileCheck bool `long:"tls-profile-check" description:"Compare the ClientHello observed on the wire with the imported TLS profile." optional:"yes" optional-value:"true"`

	// TLSProfileStrict makes a non-exact TLS profile check fail the request.
	TLSProfileStrict bool `long:"tls-profile-strict" description:"Fail if the TLS profile check is partial, unsupported, or mismatched; implies --tls-profile-check." optional:"yes" optional-value:"true"`

	// ProxyTLSProfile imports a separate JA3Proxy ClientHello profile for HTTPS proxies.
	ProxyTLSProfile string `long:"proxy-tls-profile" description:"Import a separate TLS ClientHello profile for an HTTPS proxy." value-name:"<file>"`

	// ProxyTLSProfileCheck reports and compares the HTTPS-proxy ClientHello with its imported profile.
	ProxyTLSProfileCheck bool `long:"proxy-tls-profile-check" description:"Compare the HTTPS-proxy ClientHello with --proxy-tls-profile." optional:"yes" optional-value:"true"`

	// ProxyTLSProfileStrict fails the request if the HTTPS-proxy profile check is not an exact match.
	ProxyTLSProfileStrict bool `long:"proxy-tls-profile-strict" description:"Fail if the HTTPS-proxy profile check is partial, unsupported, or mismatched; implies --proxy-tls-profile-check." optional:"yes" optional-value:"true"`

	// HTTPv11 forces to use HTTP v1.1.
	HTTPv11 bool `long:"http1.1" description:"Forces gocurl to use HTTP v1.1." optional:"yes" optional-value:"true"`

	// HTTPv2 forces to use HTTP v2.
	HTTPv2 bool `long:"http2" description:"Forces gocurl to use HTTP v2." optional:"yes" optional-value:"true"`

	// HTTPv3 forces to use HTTP v3.
	HTTPv3 bool `long:"http3" description:"Forces gocurl to use HTTP v3." optional:"yes" optional-value:"true"`

	// HTTP2 frame settings supported by x/net/http2. Empty leaves library defaults.
	H2HeaderTableSize   string `long:"h2-header-table-size"    description:"HTTP/2 SETTINGS_HEADER_TABLE_SIZE (nonzero)."                                                                 value-name:"<bytes>"`
	H2MaxFrameSize      string `long:"h2-max-frame-size"       description:"HTTP/2 SETTINGS_MAX_FRAME_SIZE (16384..16777215)."                                                            value-name:"<bytes>"`
	H2MaxHeaderListSize string `long:"h2-max-header-list-size" description:"HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE (nonzero)."                                                              value-name:"<bytes>"`
	H2PseudoOrder       string `long:"h2-pseudo-order"         description:"HTTP/2 request pseudo-header order, e.g. method,scheme,authority,path; requires --http2."                     value-name:"<names>"`
	H2SettingsOrder     string `long:"h2-settings-order"       description:"Order advertised HTTP/2 SETTINGS IDs, e.g. ENABLE_PUSH,INITIAL_WINDOW_SIZE,MAX_FRAME_SIZE; requires --http2." value-name:"<names>"`
	H2DataFrameSize     string `long:"h2-data-frame-size"      description:"Maximum outbound HTTP/2 DATA payload per frame (1..16384); requires --http2."                                 value-name:"<bytes>"`
	H2HeaderFrameSize   string `long:"h2-header-frame-size"    description:"Maximum outbound request HEADERS/CONTINUATION payload per frame (1..16384); requires --http2."                value-name:"<bytes>"`
	H2FramePadding      string `long:"h2-frame-padding"        description:"Padding bytes (1..255) on the first request HEADERS and outbound DATA frames; requires --http2."              value-name:"<bytes>"`
	H2HeaderOrder       string `long:"h2-header-order"         description:"HTTP/2 regular header-name order; listed fields first, others retain transport order."                        value-name:"<names>"`
	H2Priority          string `long:"h2-priority"             description:"Send HTTP/2 PRIORITY for the request stream: dependency:weight:exclusive (weight 1..256); requires --http2."  value-name:"<dependency:weight:exclusive>"`

	// H3AdditionalSettings carries non-standard HTTP/3 setting ID=value pairs.
	H3AdditionalSettings []string `long:"h3-setting"   description:"Additional HTTP/3 SETTINGS ID=VALUE (decimal or 0x hex); repeatable."           value-name:"<id=value>"`
	H3Datagrams          bool     `long:"h3-datagrams" description:"Enable HTTP/3 Datagrams and advertise QUIC datagram support; requires --http3."`

	QUICInitialStreamWindow            string `long:"quic-initial-stream-window"               description:"QUIC initial stream receive window for HTTP/3."                                                     value-name:"<bytes>"`
	QUICInitialMaxStreamDataBidiLocal  string `long:"quic-initial-max-stream-data-bidi-local"  description:"QUIC initial_max_stream_data_bidi_local (0..2^62-1); overrides --quic-initial-stream-window."       value-name:"<bytes>"`
	QUICInitialMaxStreamDataBidiRemote string `long:"quic-initial-max-stream-data-bidi-remote" description:"QUIC initial_max_stream_data_bidi_remote (0..2^62-1); overrides --quic-initial-stream-window."      value-name:"<bytes>"`
	QUICInitialMaxStreamDataUni        string `long:"quic-initial-max-stream-data-uni"         description:"QUIC initial_max_stream_data_uni (0..2^62-1); overrides --quic-initial-stream-window."              value-name:"<bytes>"`
	QUICInitialConnectionWindow        string `long:"quic-initial-connection-window"           description:"QUIC initial connection receive window for HTTP/3."                                                 value-name:"<bytes>"`
	QUICMaxIdleTimeoutMS               string `long:"quic-max-idle-timeout-ms"                 description:"QUIC maximum idle timeout advertised by the HTTP/3 client."                                         value-name:"<milliseconds>"`
	QUICMaxIncomingStreams             string `long:"quic-max-incoming-streams"                description:"Maximum peer-initiated bidirectional QUIC streams for HTTP/3."                                      value-name:"<count>"`
	QUICMaxIncomingUniStreams          string `long:"quic-max-incoming-uni-streams"            description:"Maximum peer-initiated unidirectional QUIC streams for HTTP/3 (at least 3)."                        value-name:"<count>"`
	QUICVersion                        string `long:"quic-version"                             description:"Force QUIC version 1 or 2 for HTTP/3."                                                              value-name:"<1|2>"`
	QUICInitialPacketSize              string `long:"quic-initial-packet-size"                 description:"Initial QUIC packet size in bytes (1200..1452) for HTTP/3."                                         value-name:"<bytes>"`
	QUICConnectionIDLength             string `long:"quic-connection-id-length"                description:"Client QUIC source connection ID length (1..20) for HTTP/3."                                        value-name:"<bytes>"`
	QUICActiveConnectionIDLimit        string `long:"quic-active-connection-id-limit"          description:"QUIC active_connection_id_limit transport parameter (2..4 supported by this transport) for HTTP/3." value-name:"<count>"`
	QUICAckDelayExponent               string `long:"quic-ack-delay-exponent"                  description:"QUIC ack_delay_exponent (0..20) for HTTP/3."                                                        value-name:"<exponent>"`
	QUICMaxAckDelayMS                  string `long:"quic-max-ack-delay-ms"                    description:"QUIC max_ack_delay transport parameter in milliseconds (0..16383) for HTTP/3."                      value-name:"<milliseconds>"`
	QUICMaxUDPPayloadSize              string `long:"quic-max-udp-payload-size"                description:"QUIC max_udp_payload_size (1200..1452 bytes supported by this transport) for HTTP/3."               value-name:"<bytes>"`
	QUICResetStreamAt                  bool   `long:"quic-reset-stream-at"                     description:"Advertise the experimental QUIC RESET_STREAM_AT extension; requires --http3."`
	QUICDisableActiveMigration         bool   `long:"quic-disable-active-migration"            description:"Advertise the QUIC disable_active_migration transport parameter; requires --http3."`
	QUICTransportParameterOrder        string `long:"quic-transport-parameter-order"           description:"Order client QUIC transport parameter IDs (decimal or 0x hex); requires --http3."                   value-name:"<ids>"`

	// ECH forces usage of Encrypted Client Hello for the request.  If other
	// ECH-related fields are not specified, the ECH configuration will be
	// received from the DNS settings.
	ECH bool `long:"ech" description:"Enables ECH support for the request." optional:"yes" optional-value:"true"`

	// ECHGrease forces sending ECH grease in the ClientHello.  This option
	// does not try to resolve the ECH configuration and is only used for
	// testing ECH grease.
	ECHGrease bool `long:"echgrease" description:"Forces sending ECH grease in the ClientHello, but does not try to resolve the ECH configuration." optional:"yes" optional-value:"true"`

	// ECHConfig is a custom ECH configuration to use for this request.  If this
	// option is specified, there will be no attempt to discover the ECH
	// configuration using DNS.
	ECHConfig string `long:"echconfig" description:"ECH configuration to use for this request. Implicitly enables --ech when specified." value-name:"<base64-encoded data>"`

	// IPv4 if configured forces usage of IP4 addresses only when doing DNS
	// resolution.
	IPv4 bool `short:"4" long:"ipv4" description:"This option tells gocurl to use IPv4 addresses only when resolving host names." optional:"yes" optional-value:"true"`

	// IPv6 if configured forces usage of IP4 addresses only when doing DNS
	// resolution.
	IPv6 bool `short:"6" long:"ipv6" description:"This option tells gocurl to use IPv6 addresses only when resolving host names." optional:"yes" optional-value:"true"`

	// DNSServers is a list of DNS servers that will be used to resolve
	// hostnames when making a request.  Encrypted DNS addresses or DNS stamps
	// can be used here.
	DNSServers string `long:"dns-servers" description:"DNS servers to use when making the request. Supports encrypted DNS: tls://, https://, quic://, sdns://" value-name:"<DNSADDR1,DNSADDR2>"`

	// Resolve allows to provide a custom address for a specific host and port
	// pair. Supports '*' instead of the host name to cover all hosts.
	Resolve []string `long:"resolve" description:"Provide a custom address for a specific host. port is ignored by gocurl. '*' can be used instead of the host name. Can be specified multiple times." value-name:"<[+]host:port:addr[,addr]...>"`

	// TLSSplitHello is an option that allows splitting TLS ClientHello in two
	// parts in order to avoid common DPI systems detecting TLS. CHUNKSIZE is
	// the size of the first bytes before ClientHello is split, DELAY is delay
	// in milliseconds before sending the second part.
	TLSSplitHello string `long:"tls-split-hello" description:"An option that allows splitting TLS ClientHello in two parts in order to avoid common DPI systems detecting TLS. CHUNKSIZE is the size of the first bytes before ClientHello is split, DELAY is delay in milliseconds before sending the second part." value-name:"<CHUNKSIZE:DELAY>"`

	// TLSRandom allows overriding the TLS ClientHello random value. Must be
	// a base64-encoded 32-byte string.
	TLSRandom string `long:"tls-random" description:"Base64-encoded 32-byte TLS ClientHello random value." value-name:"<base64>"`

	// OutputJSON enables writing output in JSON format.
	OutputJSON bool `long:"json-output" description:"Makes gocurl write machine-readable output in JSON format." optional:"yes" optional-value:"true"`

	// JSONRedactHeaders omits selected request header values from JSON metadata.
	JSONRedactHeaders []string `long:"json-redact-header" description:"Redact this request header from JSON metadata; can be specified multiple times." value-name:"<name>"`

	// OutputPath defines where to write the received data. If not set, gocurl
	// will write everything to stdout.
	OutputPath string `short:"o" long:"output" description:"Defines where to write the received data. If not set, gocurl will write everything to stdout." value-name:"<file>"`

	// Experiments allows to enable experimental configuration options.
	Experiments []string `long:"experiment" description:"Allows enabling experimental options. See the documentation for available options. Can be specified multiple times." value-name:"<name[:value]>"`

	// OHTTPGatewayURL is the URL of the Oblivious HTTP gateway where the request should be sent.
	OHTTPGatewayURL string `long:"ohttp-gateway-url" description:"URL of the Oblivious HTTP gateway where the request should be sent." value-name:"<URL>"`

	// OHTTPKeysURL is the URL from which to retrieve Oblivious HTTP KeyConfig.
	OHTTPKeysURL string `long:"ohttp-keys-url" description:"URL from which to retrieve Oblivious HTTP KeyConfig to use for encrypting the request." value-name:"<URL>"`

	// Verbose defines whether we should write the DEBUG-level log or not.
	Verbose bool `short:"v" long:"verbose" description:"Verbose output (optional)." optional:"yes" optional-value:"true"`
}

// String implements fmt.Stringer interface for Options.
func (o *Options) String() (s string) {
	b, _ := json.MarshalIndent(o, "", "    ")

	return string(b)
}

// parseOptions parses the provided args and creates the Options struct.
func parseOptions(args []string) (o *Options, err error) {
	opts := &Options{}
	parser := goFlags.NewParser(opts, goFlags.Default|goFlags.IgnoreUnknown)
	remainingArgs, err := parser.ParseArgs(args)
	if err != nil {
		return nil, err
	}

	if len(remainingArgs) != 1 && opts.URL == "" {
		return nil, fmt.Errorf("URL not found in the arguments: %v", args)
	}

	if opts.URL == "" {
		opts.URL = remainingArgs[0]
	}

	return opts, nil
}
