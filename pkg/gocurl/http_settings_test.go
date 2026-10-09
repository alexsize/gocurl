package gocurl

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
)

func TestRequestArgsHTTPSettings(t *testing.T) {
	zeroAckDelayExponent := uint8(0)
	zeroMaxAckDelay := time.Duration(0)
	bidiLocalWindow, bidiRemoteWindow, uniWindow := uint64(111), uint64(222), uint64(333)
	for _, tc := range []struct {
		request Request
		want    []string
	}{
		{Request{
			URL: "https://example.test/", HTTPVersion: "2",
			JSONRedactHeaders:    []string{"Authorization", "Cookie"},
			HTTP2Settings:        HTTP2Settings{HeaderTableSize: 8192, MaxFrameSize: 32768, MaxHeaderListSize: 65536},
			HTTP2PseudoOrder:     []string{"authority", "method", "path", "scheme"},
			HTTP2SettingsOrder:   []string{"MAX_FRAME_SIZE", "ENABLE_PUSH"},
			HTTP2DataFrameSize:   7,
			HTTP2HeaderFrameSize: 1024,
			HTTP2FramePadding:    16,
			HTTP2HeaderOrder:     []string{"x-b", "x-a"},
			HTTP2Priority:        &HTTP2Priority{Dependency: 0, Weight: 16, Exclusive: true},
		}, []string{"--json-redact-header=Authorization", "--json-redact-header=Cookie", "--h2-header-table-size=8192", "--h2-max-frame-size=32768", "--h2-max-header-list-size=65536", "--h2-pseudo-order=authority,method,path,scheme", "--h2-settings-order=MAX_FRAME_SIZE,ENABLE_PUSH", "--h2-data-frame-size=7", "--h2-header-frame-size=1024", "--h2-frame-padding=16", "--h2-header-order=x-b,x-a", "--h2-priority=0:16:true"}},
		{Request{
			URL: "https://example.test/", HTTPVersion: "3",
			HTTP3AdditionalSettings:     map[uint64]uint64{65: 0, 64: 127},
			HTTP3Datagrams:              true,
			QUICTransport:               QUICTransport{InitialStreamReceiveWindow: 65536, InitialMaxStreamDataBidiLocal: &bidiLocalWindow, InitialMaxStreamDataBidiRemote: &bidiRemoteWindow, InitialMaxStreamDataUni: &uniWindow, InitialConnectionReceiveWindow: 262144, MaxIdleTimeout: 7 * time.Second, MaxIncomingStreams: 10, MaxIncomingUniStreams: 12, Version: "2", InitialPacketSize: 1300, ConnectionIDLength: 8, ActiveConnectionIDLimit: 4, AckDelayExponent: &zeroAckDelayExponent, MaxAckDelay: &zeroMaxAckDelay, MaxUDPPayloadSize: 1350, EnableResetStreamAt: true, DisableActiveMigration: true},
			QUICTransportParameterOrder: []uint64{4, 1, 3},
		}, []string{"--h3-setting=64=127", "--h3-setting=65=0", "--h3-datagrams", "--quic-initial-stream-window=65536", "--quic-initial-max-stream-data-bidi-local=111", "--quic-initial-max-stream-data-bidi-remote=222", "--quic-initial-max-stream-data-uni=333", "--quic-initial-connection-window=262144", "--quic-max-idle-timeout-ms=7000", "--quic-max-incoming-streams=10", "--quic-max-incoming-uni-streams=12", "--quic-version=2", "--quic-initial-packet-size=1300", "--quic-connection-id-length=8", "--quic-active-connection-id-limit=4", "--quic-ack-delay-exponent=0", "--quic-max-ack-delay-ms=0", "--quic-max-udp-payload-size=1350", "--quic-reset-stream-at", "--quic-disable-active-migration", "--quic-transport-parameter-order=0x4,0x1,0x3"}},
		{Request{
			URL: "https://example.test/", ProxyURL: "https://proxy.example.test", ProxyHTTP2Connect: true,
		}, []string{"--proxy", "https://proxy.example.test", "--proxy-http2-connect"}},
		{Request{
			URL: "https://example.test/", ProxyURL: "https://proxy.example.test", ProxyInsecure: true,
		}, []string{"--proxy", "https://proxy.example.test", "--proxy-insecure"}},
	} {
		args, err := requestArgs(tc.request)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range tc.want {
			if !slices.Contains(args, want) {
				t.Errorf("requestArgs(%+v) = %q; missing %s", tc.request, args, want)
			}
		}
		if _, err := config.ParseConfig(args); err != nil {
			t.Fatalf("ParseConfig(requestArgs) = %v", err)
		}
	}

	args, err := requestArgs(Request{
		URL: "https://example.test/", HTTPVersion: "1.1", NoDefaultHeaders: true,
	})
	if err != nil {
		t.Fatalf("requestArgs(NoDefaultHeaders) error = %v", err)
	}
	if !slices.Contains(args, "--no-default-headers") {
		t.Fatalf("requestArgs(NoDefaultHeaders) = %q; missing --no-default-headers", args)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(NoDefaultHeaders request) = %v", err)
	}
	if !cfg.NoDefaultHeaders {
		t.Error("parsed config did not preserve NoDefaultHeaders")
	}
	args, err = requestArgs(Request{URL: "https://example.test/", NoDefaultHeaders: true})
	if err != nil {
		t.Fatalf("requestArgs(NoDefaultHeaders without HTTP/1.1) error = %v", err)
	}
	if _, err = config.ParseConfig(args); err == nil {
		t.Error("ParseConfig accepted NoDefaultHeaders without HTTP/1.1")
	}
}

func TestRequestArgsResolveMatchesCLIConfig(t *testing.T) {
	request := Request{
		URL: "https://resolve.example.test/",
		Resolve: map[string][]string{
			"resolve.example.test": {"192.0.2.10", "2001:db8::10"},
			"*":                    {"198.51.100.20"},
		},
	}
	args, err := requestArgs(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--resolve=*:0:198.51.100.20",
		"--resolve=resolve.example.test:0:192.0.2.10,2001:db8::10",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("requestArgs() = %q; missing %q", args, want)
		}
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	for host, want := range map[string][]string{
		"resolve.example.test": {"192.0.2.10", "2001:db8::10"},
		"*":                    {"198.51.100.20"},
	} {
		got := cfg.Resolve[host]
		if len(got) != len(want) {
			t.Fatalf("Resolve[%q] = %v; want %v", host, got, want)
		}
		for i := range want {
			if !got[i].Equal(net.ParseIP(want[i])) {
				t.Errorf("Resolve[%q][%d] = %v; want %s", host, i, got[i], want[i])
			}
		}
	}
}

func TestRequestArgsConnectToMatchesCLIConfig(t *testing.T) {
	request := Request{
		URL:       "https://connect-api.example.test:443/",
		ConnectTo: []string{"connect-api.example.test:443:127.0.0.1:8443"},
	}
	args, err := requestArgs(request)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--connect-to") || !slices.Contains(args, request.ConnectTo[0]) {
		t.Fatalf("requestArgs() = %q; want --connect-to mapping %q", args, request.ConnectTo[0])
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if got := cfg.ConnectTo["connect-api.example.test:443"]; got != "127.0.0.1:8443" {
		t.Errorf("ConnectTo mapping = %q, want 127.0.0.1:8443", got)
	}
}

func TestRequestArgsConnectToRejectsInvalidCLIFormat(t *testing.T) {
	args, err := requestArgs(Request{
		URL:       "https://connect-api.example.test/",
		ConnectTo: []string{"not-a-valid-connect-to-mapping"},
	})
	if err != nil {
		t.Fatalf("requestArgs() error = %v; expected CLI config parser to reject mapping", err)
	}
	if _, err = config.ParseConfig(args); err == nil {
		t.Fatal("ParseConfig(requestArgs()) expected invalid ConnectTo mapping error")
	}
}

func TestRequestArgsTLSVersionAndCipherSettingsMatchCLIConfig(t *testing.T) {
	request := Request{
		URL:             "https://tls-api.example.test/",
		TLSMinVersion:   "1.2",
		TLSMaxVersion:   "1.3",
		TLSCipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	args, err := requestArgs(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--tlsv1.2",
		"--tls-max=1.3",
		"--ciphers=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("requestArgs() = %q; missing %q", args, want)
		}
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if cfg.TLSMinVersion != tls.VersionTLS12 || cfg.TLSMaxVersion != tls.VersionTLS13 {
		t.Errorf(
			"TLS version bounds = %#x..%#x, want %#x..%#x",
			cfg.TLSMinVersion,
			cfg.TLSMaxVersion,
			tls.VersionTLS12,
			tls.VersionTLS13,
		)
	}
	if len(cfg.TLSCiphers) != 2 {
		t.Fatalf("TLS ciphers = %v, want two suites", cfg.TLSCiphers)
	}
}

func TestRequestArgsPostQuantumMatchesCLIConfig(t *testing.T) {
	args, err := requestArgs(Request{URL: "https://example.test/", PostQuantum: true})
	if err != nil {
		t.Fatalf("requestArgs() error = %v", err)
	}
	if !slices.Contains(args, "--experiment=pq") {
		t.Fatalf("requestArgs() = %q, want --experiment=pq", args)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs()) error = %v", err)
	}
	if _, ok := cfg.Experiments[config.ExpPostQuantum]; !ok {
		t.Errorf("Experiments = %v, want post-quantum experiment", cfg.Experiments)
	}
	defaultArgs, err := requestArgs(Request{URL: "https://example.test/"})
	if err != nil {
		t.Fatalf("requestArgs() with zero value error = %v", err)
	}
	if slices.Contains(defaultArgs, "--experiment=pq") {
		t.Errorf("zero-value Request unexpectedly enables post-quantum TLS: %q", defaultArgs)
	}
	_, err = requestArgs(Request{
		URL: "https://example.test/", PostQuantum: true,
		TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{Preset: "chrome-120"}},
	})
	if err == nil || !strings.Contains(err.Error(), "post-quantum") {
		t.Errorf("manual ClientHello + PostQuantum error = %v, want incompatibility error", err)
	}
	if _, err = requestArgs(Request{URL: "https://example.test/", PostQuantum: true, HTTPVersion: "3"}); err == nil {
		t.Error("PostQuantum with HTTP/3 unexpectedly accepted")
	}
	if _, err = requestArgs(Request{URL: "http://example.test/", PostQuantum: true}); err == nil {
		t.Error("PostQuantum with plain HTTP unexpectedly accepted")
	}
}

func TestRequestArgsRejectsInvalidTLSVersionAndCipherSettings(t *testing.T) {
	for _, request := range []Request{
		{URL: "https://example.test/", TLSMinVersion: "1.1"},
		{URL: "https://example.test/", TLSMaxVersion: "1.4"},
		{URL: "https://example.test/", TLSMinVersion: "1.3", TLSMaxVersion: "1.2"},
		{URL: "https://example.test/", TLSCipherSuites: []string{"TLS_AES_128_GCM_SHA256 invalid"}},
		{URL: "https://example.test/", TLSCipherSuites: []string{""}},
		{URL: "https://example.test/", TLSMinVersion: "1.3", TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{Preset: "chrome-120"}}},
	} {
		if _, err := requestArgs(request); err == nil {
			t.Errorf("requestArgs(%+v) expected validation error", request)
		}
	}
}

func TestRequestArgsConnectTimeoutMatchesCLIConfig(t *testing.T) {
	args, err := requestArgs(Request{URL: "http://example.test/", ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--connect-timeout") || !slices.Contains(args, "3") {
		t.Fatalf("requestArgs() = %q; want --connect-timeout 3", args)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if cfg.ConnectTimeout != 3 {
		t.Errorf("ConnectTimeout = %d seconds, want 3", cfg.ConnectTimeout)
	}
	for _, timeout := range []time.Duration{-time.Second, time.Millisecond} {
		if _, err = requestArgs(Request{URL: "http://example.test/", ConnectTimeout: timeout}); err == nil {
			t.Errorf("requestArgs(ConnectTimeout=%s) expected validation error", timeout)
		}
	}
	args, err = requestArgs(Request{URL: "http://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--connect-timeout") {
		t.Errorf("zero ConnectTimeout unexpectedly changed CLI defaults: %q", args)
	}
}

func TestRequestArgsOHTTPMatchesCLIConfig(t *testing.T) {
	request := Request{
		URL:             "https://hidden.example.test/path",
		OHTTPGatewayURL: "https://gateway.example.test/ohttp",
		OHTTPKeysURL:    "https://keys.example.test/config",
	}
	args, err := requestArgs(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--ohttp-gateway-url=https://gateway.example.test/ohttp",
		"--ohttp-keys-url=https://keys.example.test/config",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("requestArgs() = %q; missing %q", args, want)
		}
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if cfg.OHTTPGatewayURL.String() != request.OHTTPGatewayURL || cfg.OHTTPKeysURL.String() != request.OHTTPKeysURL {
		t.Errorf(
			"parsed OHTTP URLs = %v and %v; want %q and %q",
			cfg.OHTTPGatewayURL,
			cfg.OHTTPKeysURL,
			request.OHTTPGatewayURL,
			request.OHTTPKeysURL,
		)
	}
	for _, partial := range []Request{
		{URL: request.URL, OHTTPGatewayURL: request.OHTTPGatewayURL},
		{URL: request.URL, OHTTPKeysURL: request.OHTTPKeysURL},
	} {
		if _, err = requestArgs(partial); err == nil {
			t.Errorf("requestArgs(%+v) expected paired OHTTP URL validation error", partial)
		}
	}
}

func TestRequestArgsPreservesStructuredHeaderValue(t *testing.T) {
	args, err := requestArgs(Request{
		URL:     "https://headers.example.test/",
		Headers: []Header{{Name: "X-Exact-Value", Value: "preserved"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if got := cfg.Headers.Get("X-Exact-Value"); got != "preserved" {
		t.Errorf("parsed header value = %q, want exact API value %q", got, "preserved")
	}
}

func TestRequestArgsDNSControlsMatchCLIConfig(t *testing.T) {
	for _, tc := range []struct {
		version string
		flag    string
		ipv4    bool
		ipv6    bool
	}{
		{version: "4", flag: "--ipv4", ipv4: true},
		{version: "6", flag: "--ipv6", ipv6: true},
	} {
		request := Request{
			URL:        "http://dns-api.example.test/",
			IPVersion:  tc.version,
			DNSServers: []string{"127.0.0.1:5300", "tls://dns.example.test"},
		}
		args, err := requestArgs(request)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(args, tc.flag) ||
			!slices.Contains(args, "--dns-servers=127.0.0.1:5300,tls://dns.example.test") {
			t.Errorf("requestArgs() = %q; missing %s or DNS upstream list", args, tc.flag)
		}
		cfg, parseErr := config.ParseConfig(args)
		if parseErr != nil {
			t.Fatalf("ParseConfig(requestArgs) = %v", parseErr)
		}
		if cfg.IPv4 != tc.ipv4 || cfg.IPv6 != tc.ipv6 || len(cfg.DNSServers) != 2 {
			t.Errorf(
				"parsed DNS controls = IPv4:%t IPv6:%t upstreams:%d; want IPv4:%t IPv6:%t upstreams:2",
				cfg.IPv4,
				cfg.IPv6,
				len(cfg.DNSServers),
				tc.ipv4,
				tc.ipv6,
			)
		}
	}
}

func TestRequestArgsRejectsInvalidDNSControls(t *testing.T) {
	for _, request := range []Request{
		{URL: "http://example.test/", IPVersion: "5"},
		{URL: "http://example.test/", DNSServers: []string{"127.0.0.1:53", ""}},
		{URL: "http://example.test/", DNSServers: []string{" 127.0.0.1:53"}},
		{URL: "http://example.test/", DNSServers: []string{"127.0.0.1:53,127.0.0.2:53"}},
	} {
		if _, err := requestArgs(request); err == nil {
			t.Errorf("requestArgs(%+v) expected validation error", request)
		}
	}
}

func TestRequestArgsResolveRejectsInvalidEntries(t *testing.T) {
	for _, resolve := range []map[string][]string{
		{"example.test": nil},
		{"example.test": {"not-an-ip"}},
		{"": {"192.0.2.1"}},
	} {
		if _, err := requestArgs(Request{URL: "https://example.test/", Resolve: resolve}); err == nil {
			t.Errorf("requestArgs(Resolve=%v) expected error", resolve)
		}
	}
}

func TestRequestArgsTLSServerNameMatchesCLIConfig(t *testing.T) {
	args, err := requestArgs(Request{URL: "https://url.example.test/", TLSServerName: "sni.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--tls-servername=sni.example.test") {
		t.Fatalf("requestArgs() = %q, want TLS SNI override", args)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs) = %v", err)
	}
	if cfg.TLSServerName != "sni.example.test" {
		t.Fatalf("TLSServerName = %q, want sni.example.test", cfg.TLSServerName)
	}

	args, err = requestArgs(Request{URL: "https://url.example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--tls-servername=") {
		t.Fatalf("zero-value TLSServerName unexpectedly changed args: %q", args)
	}
}

func TestRequestArgsRejectsConflictingManualTLSServerNames(t *testing.T) {
	_, err := requestArgs(Request{
		URL:           "https://url.example.test/",
		TLSServerName: "top-level.example.test",
		TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{
			Preset: "chrome-120", ServerName: "manual.example.test",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicts with TLSProfile.ClientHello.ServerName") {
		t.Fatalf("requestArgs() error = %v, want conflicting SNI error", err)
	}
}

func TestRequestArgsRejectsFractionalQUICIdleTimeout(t *testing.T) {
	_, err := requestArgs(
		Request{
			URL:           "https://example.test/",
			HTTPVersion:   "3",
			QUICTransport: QUICTransport{MaxIdleTimeout: time.Millisecond + time.Microsecond},
		},
	)
	if err == nil {
		t.Fatal("expected millisecond precision error")
	}
}

func TestRequestArgsECHOptionsMatchCLIConfig(t *testing.T) {
	const validECHConfig = "AEX+DQBBowAgACA+MDtQ9ShQuke+cqO01oHPiKeg1UDwoyeh5EL+9wfWQwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
	for _, tc := range []struct {
		name       string
		request    Request
		wantArg    string
		wantECH    bool
		wantGrease bool
		wantConfig bool
	}{
		{name: "ECH discovery", request: Request{URL: "https://example.test/", ECH: true}, wantArg: "--ech", wantECH: true},
		{name: "ECH GREASE", request: Request{URL: "https://example.test/", ECHGrease: true}, wantArg: "--echgrease", wantGrease: true},
		{name: "explicit ECH config", request: Request{URL: "https://example.test/", ECHConfig: validECHConfig}, wantArg: "--echconfig=" + validECHConfig, wantECH: true, wantConfig: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := requestArgs(tc.request)
			if err != nil {
				t.Fatalf("requestArgs() error = %v", err)
			}
			if !slices.Contains(args, tc.wantArg) {
				t.Fatalf("requestArgs() = %q, want %q", args, tc.wantArg)
			}
			cfg, err := config.ParseConfig(args)
			if err != nil {
				t.Fatalf("ParseConfig(requestArgs()) error = %v", err)
			}
			if cfg.ECH != tc.wantECH || cfg.ECHGrease != tc.wantGrease || (len(cfg.ECHConfigs) > 0) != tc.wantConfig {
				t.Fatalf("parsed ECH config = ECH:%t GREASE:%t Configs:%d; want ECH:%t GREASE:%t ConfigPresent:%t",
					cfg.ECH, cfg.ECHGrease, len(cfg.ECHConfigs), tc.wantECH, tc.wantGrease, tc.wantConfig)
			}
		})
	}
}

func TestRequestArgsTLSRandomMatchesCLIConfig(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	args, err := requestArgs(Request{URL: "https://example.test/", TLSRandom: want})
	if err != nil {
		t.Fatalf("requestArgs() error = %v", err)
	}
	encoded := "--tls-random=" + base64.StdEncoding.EncodeToString(want)
	if !slices.Contains(args, encoded) {
		t.Fatalf("requestArgs() = %q, want %q", args, encoded)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs()) error = %v", err)
	}
	if !slices.Equal(cfg.TLSRandom, want) {
		t.Fatalf("parsed TLSRandom = %x, want %x", cfg.TLSRandom, want)
	}
	if args, err = requestArgs(
		Request{URL: "https://example.test/"},
	); err != nil || len(args) != 1 ||
		args[0] != "https://example.test/" {
		t.Fatalf("default request args = %q, error %v; TLS random should remain unspecified", args, err)
	}
	for _, length := range []int{31, 33} {
		if _, err = requestArgs(Request{URL: "https://example.test/", TLSRandom: make([]byte, length)}); err == nil {
			t.Errorf("requestArgs() accepted %d-byte TLSRandom, want validation error", length)
		}
	}
}

func TestRequestArgsTLSSplitHelloMatchesCLIConfig(t *testing.T) {
	args, err := requestArgs(Request{
		URL:           "https://example.test/",
		TLSSplitHello: &TLSSplitHello{FirstChunkSize: 7, Delay: 25 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("requestArgs() error = %v", err)
	}
	if !slices.Contains(args, "--tls-split-hello=7:25") {
		t.Fatalf("requestArgs() = %q, want --tls-split-hello=7:25", args)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs()) error = %v", err)
	}
	if cfg.TLSSplitChunkSize != 7 || cfg.TLSSplitDelay != 25 {
		t.Fatalf("parsed split config = %d:%d, want 7:25", cfg.TLSSplitChunkSize, cfg.TLSSplitDelay)
	}
	for _, split := range []*TLSSplitHello{
		{FirstChunkSize: 0},
		{FirstChunkSize: -1},
		{FirstChunkSize: 5, Delay: -time.Millisecond},
		{FirstChunkSize: 5, Delay: 500 * time.Microsecond},
	} {
		if _, err = requestArgs(Request{URL: "https://example.test/", TLSSplitHello: split}); err == nil {
			t.Errorf("requestArgs() accepted invalid TLSSplitHello %+v", split)
		}
	}
}

func TestRequestArgsQUICConfigParity(t *testing.T) {
	streamBidiLocal, streamBidiRemote, streamUni := uint64(111), uint64(222), uint64(333)
	ackDelayExponent := uint8(0)
	maxAckDelay := time.Duration(0)
	request := Request{
		URL: "https://example.test/", HTTPVersion: "3",
		HTTP3AdditionalSettings: map[uint64]uint64{64: 127, 65: 0},
		HTTP3Datagrams:          true,
		QUICTransport: QUICTransport{
			InitialStreamReceiveWindow:     65536,
			InitialMaxStreamDataBidiLocal:  &streamBidiLocal,
			InitialMaxStreamDataBidiRemote: &streamBidiRemote,
			InitialMaxStreamDataUni:        &streamUni,
			InitialConnectionReceiveWindow: 262144,
			MaxIdleTimeout:                 7 * time.Second,
			MaxIncomingStreams:             10,
			MaxIncomingUniStreams:          12,
			Version:                        "2",
			InitialPacketSize:              1300,
			ConnectionIDLength:             8,
			ActiveConnectionIDLimit:        4,
			AckDelayExponent:               &ackDelayExponent,
			MaxAckDelay:                    &maxAckDelay,
			MaxUDPPayloadSize:              1350,
			EnableResetStreamAt:            true,
			DisableActiveMigration:         true,
		},
		QUICTransportParameterOrder: []uint64{4, 1, 3},
	}

	args, err := requestArgs(request)
	if err != nil {
		t.Fatalf("requestArgs() error = %v", err)
	}
	cfg, err := config.ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(requestArgs()) error = %v", err)
	}
	if !cfg.ForceHTTP3 || !cfg.HTTP3Datagrams {
		t.Fatalf("HTTP/3 settings config = %+v, does not match request", cfg)
	}
	if !slices.Equal(cfg.QUICTransportParameterOrder, request.QUICTransportParameterOrder) {
		t.Errorf(
			"QUIC parameter order = %v, want %v",
			cfg.QUICTransportParameterOrder,
			request.QUICTransportParameterOrder,
		)
	}
	for id, want := range request.HTTP3AdditionalSettings {
		if got, ok := cfg.HTTP3AdditionalSettings[id]; !ok || got != want {
			t.Errorf("HTTP/3 setting %d = %d, present %t; want %d", id, got, ok, want)
		}
	}
	assertRequestQUICFlowControlParity(t, cfg.QUICTransport, request.QUICTransport)
	assertRequestQUICWireControlsParity(t, cfg.QUICTransport, request.QUICTransport)
}

func TestRequestArgsManualTLSClientHelloProfile(t *testing.T) {
	args, err := requestArgs(Request{
		URL: "https://example.test/",
		TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{
			Preset: "chrome-120", ServerName: "sni.example.test",
		}},
	})
	if err != nil {
		t.Fatalf("requestArgs() error = %v", err)
	}
	if !slices.Contains(args, "--tls-servername=sni.example.test") {
		t.Fatalf("requestArgs() = %q, want manual SNI override", args)
	}
	for _, profile := range []*TLSProfile{
		{ProfilePath: "profile.json", ClientHello: &TLSClientHello{Preset: "chrome-120"}},
		{Check: true, ClientHello: &TLSClientHello{Preset: "chrome-120"}},
		{Strict: true, ClientHello: &TLSClientHello{Preset: "chrome-120"}},
	} {
		if _, err = requestArgs(Request{URL: "https://example.test/", TLSProfile: profile}); err == nil {
			t.Errorf("requestArgs() accepted conflicting TLS profile %+v", profile)
		}
	}
}

func assertRequestQUICFlowControlParity(t *testing.T, got config.QUICTransport, want QUICTransport) {
	t.Helper()
	if got.InitialStreamReceiveWindow != want.InitialStreamReceiveWindow ||
		got.InitialMaxStreamDataBidiLocal != *want.InitialMaxStreamDataBidiLocal ||
		got.InitialMaxStreamDataBidiRemote != *want.InitialMaxStreamDataBidiRemote ||
		got.InitialMaxStreamDataUni != *want.InitialMaxStreamDataUni ||
		got.InitialConnectionReceiveWindow != want.InitialConnectionReceiveWindow ||
		got.MaxIdleTimeout != want.MaxIdleTimeout ||
		got.MaxIncomingStreams != want.MaxIncomingStreams ||
		got.MaxIncomingUniStreams != want.MaxIncomingUniStreams {
		t.Errorf("parsed QUIC transport = %+v, does not match request %+v", got, want)
	}
}

func assertRequestQUICWireControlsParity(t *testing.T, got config.QUICTransport, want QUICTransport) {
	t.Helper()
	if got.Version != want.Version ||
		got.InitialPacketSize != want.InitialPacketSize ||
		got.ConnectionIDLength != want.ConnectionIDLength ||
		got.ActiveConnectionIDLimit != want.ActiveConnectionIDLimit ||
		got.AckDelayExponent != 0 || !got.AckDelayExponentSet ||
		got.MaxAckDelay != 0 || !got.MaxAckDelaySet ||
		got.MaxUDPPayloadSize != want.MaxUDPPayloadSize ||
		got.EnableResetStreamAt != want.EnableResetStreamAt ||
		got.DisableActiveMigration != want.DisableActiveMigration {
		t.Errorf("parsed QUIC transport = %+v, does not match request %+v", got, want)
	}
}
