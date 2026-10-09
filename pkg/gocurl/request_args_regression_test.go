package gocurl

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRequestArgsPreservesCombinedArgumentOrder(t *testing.T) {
	request := Request{
		URL: "https://example.test/?q=a:b", Method: "POST", RequestTarget: "/custom?q=a:b",
		TLSServerName: "sni.example.test", TLSMinVersion: "1.2", TLSMaxVersion: "1.3",
		TLSCipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		NoDefaultHeaders: true, JSONRedactHeaders: []string{"X-Private", "Authorization"},
		HTTP2Settings:      HTTP2Settings{HeaderTableSize: 1024, MaxFrameSize: 16384, MaxHeaderListSize: 4096},
		HTTP2PseudoOrder:   []string{"method", "scheme", "authority", "path"},
		HTTP2SettingsOrder: []string{"HEADER_TABLE_SIZE", "MAX_FRAME_SIZE"},
		HTTP2DataFrameSize: 512, HTTP2HeaderFrameSize: 1024, HTTP2FramePadding: 7,
		HTTP2HeaderOrder: []string{"x-first", "x-repeat"},
		HTTP2Priority:    &HTTP2Priority{Dependency: 0, Weight: 256, Exclusive: true},
		ProxyURL:         "https://proxy.example.test:8443", ProxyInsecure: true,
		ConnectTimeout: 3 * time.Second,
		ConnectTo:      []string{"example.test:443:first.test:443", "example.test:443:last.test:443"},
		Resolve:        map[string][]string{"z.test": {"::1"}, "a.test": {"127.0.0.1", "127.0.0.2"}},
		IPVersion:      "4", DNSServers: []string{"127.0.0.1:53", "tls://dns.example.test"},
		ProxyHTTP2Connect: true, Insecure: true, ECH: true, ECHGrease: true, ECHConfig: "config==",
		OHTTPGatewayURL: "https://gateway.test/", OHTTPKeysURL: "https://gateway.test/keys",
		TLSRandom: make([]byte, 32), TLSSplitHello: &TLSSplitHello{FirstChunkSize: 7, Delay: 25 * time.Millisecond},
		HTTPVersion: "2",
		TLSProfile: &TLSProfile{
			ProfilePath: "target.json", Strict: true, Check: true,
			ProxyProfilePath: "proxy.json", ProxyStrict: true, ProxyCheck: true,
		},
		Headers: []Header{{Name: "X-Repeat", Value: " first: value"}, {Name: "X-Repeat", Value: "second"}},
	}
	want := []string{
		"--tls-servername=sni.example.test", "--tlsv1.2", "--tls-max=1.3",
		"--ciphers=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"--request", "POST", "--request-target=/custom?q=a:b", "--no-default-headers",
		"--json-redact-header=X-Private", "--json-redact-header=Authorization",
		"--h2-header-table-size=1024", "--h2-max-frame-size=16384", "--h2-max-header-list-size=4096",
		"--h2-pseudo-order=method,scheme,authority,path", "--h2-settings-order=HEADER_TABLE_SIZE,MAX_FRAME_SIZE",
		"--h2-data-frame-size=512", "--h2-header-frame-size=1024", "--h2-frame-padding=7",
		"--h2-header-order=x-first,x-repeat", "--h2-priority=0:256:true",
		"--proxy", "https://proxy.example.test:8443", "--proxy-insecure", "--connect-timeout", "3",
		"--connect-to", "example.test:443:first.test:443", "--connect-to", "example.test:443:last.test:443",
		"--resolve=a.test:0:127.0.0.1,127.0.0.2", "--resolve=z.test:0:::1", "--ipv4",
		"--dns-servers=127.0.0.1:53,tls://dns.example.test", "--proxy-http2-connect", "--insecure",
		"--ech", "--echgrease", "--echconfig=config==",
		"--ohttp-gateway-url=https://gateway.test/", "--ohttp-keys-url=https://gateway.test/keys",
		"--tls-random=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--tls-split-hello=7:25", "--http2",
		"--tls-profile", "target.json", "--tls-profile-strict", "--proxy-tls-profile", "proxy.json",
		"--proxy-tls-profile-strict", "--header", "X-Repeat: first: value", "--header", "X-Repeat:second",
		"https://example.test/?q=a:b",
	}
	assertRequestArgsForTest(t, request, want)
}

func TestRequestArgsPreservesQUICOrderAndExplicitZeros(t *testing.T) {
	zeroWindow := uint64(0)
	zeroExponent := uint8(0)
	zeroDelay := time.Duration(0)
	request := Request{
		URL: "https://example.test/", HTTPVersion: "3",
		HTTP3AdditionalSettings: map[uint64]uint64{65: 0, 64: 127}, HTTP3Datagrams: true,
		QUICTransport: QUICTransport{
			InitialStreamReceiveWindow:    65536,
			InitialMaxStreamDataBidiLocal: &zeroWindow, InitialMaxStreamDataBidiRemote: &zeroWindow,
			InitialMaxStreamDataUni: &zeroWindow, InitialConnectionReceiveWindow: 262144,
			MaxIdleTimeout: 7 * time.Second, MaxIncomingStreams: 10, MaxIncomingUniStreams: 12,
			Version: "2", InitialPacketSize: 1300, ConnectionIDLength: 8, ActiveConnectionIDLimit: 4,
			AckDelayExponent: &zeroExponent, MaxAckDelay: &zeroDelay, MaxUDPPayloadSize: 1350,
			EnableResetStreamAt: true, DisableActiveMigration: true,
		},
		QUICTransportParameterOrder: []uint64{4, 1, 3},
	}
	want := []string{
		"--h3-setting=64=127", "--h3-setting=65=0", "--h3-datagrams", "--quic-initial-stream-window=65536",
		"--quic-initial-max-stream-data-bidi-local=0", "--quic-initial-max-stream-data-bidi-remote=0",
		"--quic-initial-max-stream-data-uni=0", "--quic-initial-connection-window=262144",
		"--quic-max-idle-timeout-ms=7000", "--quic-max-incoming-streams=10", "--quic-max-incoming-uni-streams=12",
		"--quic-version=2", "--quic-initial-packet-size=1300", "--quic-connection-id-length=8",
		"--quic-active-connection-id-limit=4", "--quic-ack-delay-exponent=0", "--quic-max-ack-delay-ms=0",
		"--quic-max-udp-payload-size=1350", "--quic-reset-stream-at", "--quic-disable-active-migration",
		"--quic-transport-parameter-order=0x4,0x1,0x3", "--http3", "https://example.test/",
	}
	assertRequestArgsForTest(t, request, want)
	if zeroWindow != 0 || zeroExponent != 0 || zeroDelay != 0 {
		t.Fatal("requestArgs mutated explicit-zero options")
	}
}

func TestRequestArgsPreservesDefaultsAndManualTLS(t *testing.T) {
	assertRequestArgsForTest(t, Request{URL: "https://example.test/"}, []string{"https://example.test/"})
	assertRequestArgsForTest(t, Request{URL: "https://example.test/", PostQuantum: true},
		[]string{"--experiment=pq", "https://example.test/"})
	assertRequestArgsForTest(t, Request{URL: "https://example.test/", TLSProfile: &TLSProfile{
		ClientHello: &TLSClientHello{Preset: "chrome-120", ServerName: "sni.test"},
	}}, []string{"--tls-servername=sni.test", "https://example.test/"})
}

func TestRequestArgsPreservesValidationPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request Request
		want    string
	}{
		{"URL first", Request{PostQuantum: true, TLSMinVersion: "bad"}, "URL is required"},
		{
			"PQ URL before TLS",
			Request{URL: "http://example.test/", PostQuantum: true, TLSMinVersion: "bad"},
			"post-quantum TLS requires an https URL",
		},
		{"manual TLS before version", Request{
			URL: "https://example.test/", TLSMinVersion: "bad",
			TLSProfile: &TLSProfile{ProfilePath: "profile.json", ClientHello: &TLSClientHello{}},
		}, "mutually exclusive"},
		{"version before QUIC", Request{
			URL: "https://example.test/", TLSMinVersion: "bad",
			QUICTransport: QUICTransport{MaxIdleTimeout: time.Nanosecond},
		}, "unsupported TLSMinVersion"},
		{"QUIC before routing", Request{
			URL: "https://example.test/", ConnectTimeout: -time.Second,
			QUICTransport: QUICTransport{MaxIdleTimeout: time.Nanosecond},
		}, "QUIC MaxIdleTimeout"},
		{"routing before DNS", Request{
			URL: "https://example.test/", ConnectTimeout: -time.Second,
			IPVersion: "bad",
		}, "ConnectTimeout"},
		{"DNS before OHTTP", Request{
			URL: "https://example.test/", IPVersion: "bad",
			OHTTPGatewayURL: "https://gateway.test/",
		}, "unsupported IPVersion"},
		{"OHTTP before TLS wire", Request{
			URL: "https://example.test/", OHTTPGatewayURL: "https://gateway.test/",
			TLSRandom: []byte{1},
		}, "must be specified together"},
		{"TLS wire before HTTP", Request{
			URL: "https://example.test/", TLSRandom: []byte{1},
			HTTPVersion: "bad",
		}, "TLSRandom must contain exactly 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := requestArgs(tc.request)
			if args != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("requestArgs = %q, %v; want nil args and error containing %q", args, err, tc.want)
			}
		})
	}
}

func assertRequestArgsForTest(t *testing.T, request Request, want []string) {
	t.Helper()
	for repeat := 0; repeat < 20; repeat++ {
		got, err := requestArgs(request)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("requestArgs = %q; want %q", got, want)
		}
	}
}
