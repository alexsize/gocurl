package gocurl

import (
	"encoding/base64"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
)

// TestRequestFamiliesMatchIndependentCLIConfig compares validated configurations,
// not just flag presence. CLI arguments are independent of requestArgs output.
func TestRequestFamiliesMatchIndependentCLIConfig(t *testing.T) {
	for _, tc := range apiCLIParityFamilies() {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.request
			request.URL = "https://example.test/contract?visible=yes"
			args, err := requestArgs(request)
			if err != nil {
				t.Fatal(err)
			}
			got, err := config.ParseConfig(args)
			if err != nil {
				t.Fatalf("API configuration: %v", err)
			}
			want, err := config.ParseConfig(append(slices.Clone(tc.cli), request.URL))
			if err != nil {
				t.Fatalf("independent CLI configuration: %v", err)
			}
			// RawOptions is a logging representation, not the validated contract.
			got.RawOptions, want.RawOptions = nil, nil
			if len(got.DNSServers) != len(want.DNSServers) {
				t.Fatalf("DNS upstream count API=%d CLI=%d", len(got.DNSServers), len(want.DNSServers))
			}
			for i, upstream := range got.DNSServers {
				if upstream.Address() != want.DNSServers[i].Address() {
					t.Errorf("DNS upstream %d API=%s CLI=%s", i, upstream.Address(), want.DNSServers[i].Address())
				}
				_ = upstream.Close()
				_ = want.DNSServers[i].Close()
			}
			got.DNSServers, want.DNSServers = nil, nil
			if !reflect.DeepEqual(got, want) {
				t.Errorf("validated API configuration differs from CLI:\nAPI: %+v\nCLI: %+v", got, want)
			}
		})
	}
}

type apiCLIParityFamily struct {
	name    string
	request Request
	cli     []string
}

func apiCLIParityFamilies() []apiCLIParityFamily {
	const profile = "../../internal/client/utlsengine/testdata/profile-v1-valid.json"
	random := make([]byte, 32)
	zero, remote := uint64(0), uint64(222)
	exponent, delay := uint8(0), time.Duration(0)
	return []apiCLIParityFamily{
		{"defaults", Request{}, nil},
		{
			"HTTP1-metadata",
			Request{
				Method: "PATCH", HTTPVersion: "1.1", RequestTarget: "/custom?q=1",
				NoDefaultHeaders: true, JSONRedactHeaders: []string{"authorization"},
				Headers: []Header{{Name: "X-Order", Value: "first"}, {Name: "x-order", Value: "second"}},
			},
			[]string{
				"-X", "PATCH", "--http1.1", "--request-target=/custom?q=1", "--no-default-headers",
				"--json-redact-header=authorization", "-H", "X-Order:first", "-H", "x-order:second",
			},
		},
		{
			"TLS-wire",
			Request{
				TLSMinVersion: "1.2", TLSMaxVersion: "1.2", TLSServerName: "sni.example.test",
				TLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, TLSRandom: random,
				TLSSplitHello: &TLSSplitHello{FirstChunkSize: 5, Delay: 20 * time.Millisecond},
			},
			[]string{
				"--tlsv1.2",
				"--tls-max=1.2",
				"--tls-servername=sni.example.test",
				"--ciphers=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"--tls-random=" + base64.StdEncoding.EncodeToString(random),
				"--tls-split-hello=5:20",
			},
		},
		{
			"routing",
			Request{
				ConnectTimeout: 2 * time.Second,
				ConnectTo:      []string{"example.test:443:127.0.0.1:8443"},
				Resolve:        map[string][]string{"example.test": {"127.0.0.1", "::1"}, "*": {"127.0.0.2"}},
				IPVersion:      "4", DNSServers: []string{"127.0.0.1:5353", "127.0.0.2:5353"},
			},
			[]string{
				"--connect-timeout=2", "--connect-to=example.test:443:127.0.0.1:8443",
				"--resolve=*:0:127.0.0.2", "--resolve=example.test:0:127.0.0.1,::1", "--ipv4",
				"--dns-servers=127.0.0.1:5353,127.0.0.2:5353",
			},
		},
		{"IPv6", Request{IPVersion: "6"}, []string{"--ipv6"}},
		{
			"proxy-policies",
			Request{
				ProxyURL: "https://127.0.0.1:8443", ProxyHTTP2Connect: true,
				ProxyInsecure: true, Insecure: true,
			},
			[]string{"-x", "https://127.0.0.1:8443", "--proxy-http2-connect", "--proxy-insecure", "-k"},
		},
		{
			"HTTP2",
			Request{
				HTTPVersion: "2", HTTP2Settings: HTTP2Settings{
					HeaderTableSize: 8192,
					MaxFrameSize:    32768, MaxHeaderListSize: 65536,
				}, HTTP2PseudoOrder: []string{"path", "authority", "method", "scheme"},
				HTTP2SettingsOrder: []string{"MAX_FRAME_SIZE", "HEADER_TABLE_SIZE"}, HTTP2DataFrameSize: 1024,
				HTTP2HeaderFrameSize: 512, HTTP2FramePadding: 8, HTTP2HeaderOrder: []string{"x-first", "user-agent"},
				HTTP2Priority: &HTTP2Priority{Dependency: 3, Weight: 256, Exclusive: true},
			},
			[]string{
				"--http2",
				"--h2-header-table-size=8192",
				"--h2-max-frame-size=32768",
				"--h2-max-header-list-size=65536",
				"--h2-pseudo-order=path,authority,method,scheme",
				"--h2-settings-order=MAX_FRAME_SIZE,HEADER_TABLE_SIZE",
				"--h2-data-frame-size=1024",
				"--h2-header-frame-size=512",
				"--h2-frame-padding=8",
				"--h2-header-order=x-first,user-agent",
				"--h2-priority=3:256:true",
			},
		},
		{
			"HTTP3-QUIC",
			Request{
				HTTPVersion:    "3",
				HTTP3Datagrams: true,
				HTTP3AdditionalSettings: map[uint64]uint64{
					64: 127,
					65: 0,
				},
				QUICTransportParameterOrder: []uint64{4, 1, 5},
				QUICTransport: QUICTransport{
					InitialStreamReceiveWindow: 65536, InitialMaxStreamDataBidiLocal: &zero,
					InitialMaxStreamDataBidiRemote: &remote, InitialMaxStreamDataUni: &zero,
					InitialConnectionReceiveWindow: 262144, MaxIdleTimeout: 7 * time.Second,
					MaxIncomingStreams: 10, MaxIncomingUniStreams: 12, Version: "2", InitialPacketSize: 1300,
					ConnectionIDLength: 8, ActiveConnectionIDLimit: 4, AckDelayExponent: &exponent, MaxAckDelay: &delay,
					MaxUDPPayloadSize: 1350, EnableResetStreamAt: true, DisableActiveMigration: true,
				},
			},
			[]string{
				"--http3",
				"--h3-datagrams",
				"--h3-setting=64=127",
				"--h3-setting=65=0",
				"--quic-transport-parameter-order=4,1,5",
				"--quic-initial-stream-window=65536",
				"--quic-initial-max-stream-data-bidi-local=0",
				"--quic-initial-max-stream-data-bidi-remote=222",
				"--quic-initial-max-stream-data-uni=0",
				"--quic-initial-connection-window=262144",
				"--quic-max-idle-timeout-ms=7000",
				"--quic-max-incoming-streams=10",
				"--quic-max-incoming-uni-streams=12",
				"--quic-version=2",
				"--quic-initial-packet-size=1300",
				"--quic-connection-id-length=8",
				"--quic-active-connection-id-limit=4",
				"--quic-ack-delay-exponent=0",
				"--quic-max-ack-delay-ms=0",
				"--quic-max-udp-payload-size=1350",
				"--quic-reset-stream-at",
				"--quic-disable-active-migration",
			},
		},
		{"ECH", Request{ECH: true}, []string{"--ech"}},
		{"ECH-GREASE", Request{ECHGrease: true}, []string{"--echgrease"}},
		{"PQ", Request{PostQuantum: true}, []string{"--experiment=pq"}},
		{
			"OHTTP",
			Request{OHTTPGatewayURL: "http://127.0.0.1/gateway", OHTTPKeysURL: "http://127.0.0.1/keys"},
			[]string{"--ohttp-gateway-url=http://127.0.0.1/gateway", "--ohttp-keys-url=http://127.0.0.1/keys"},
		},
		{
			"profiles-check",
			Request{HTTPVersion: "1.1", ProxyURL: "https://127.0.0.1:8443", TLSProfile: &TLSProfile{
				ProfilePath: profile, Check: true, ProxyProfilePath: profile, ProxyCheck: true,
			}},
			[]string{
				"--http1.1", "--proxy=https://127.0.0.1:8443", "--tls-profile=" + profile, "--tls-profile-check",
				"--proxy-tls-profile=" + profile, "--proxy-tls-profile-check",
			},
		},
		{
			"profiles-strict-implies-check",
			Request{HTTPVersion: "1.1", ProxyURL: "https://127.0.0.1:8443", TLSProfile: &TLSProfile{
				ProfilePath: profile, Strict: true, ProxyProfilePath: profile, ProxyStrict: true,
			}},
			[]string{
				"--http1.1", "--proxy=https://127.0.0.1:8443", "--tls-profile=" + profile, "--tls-profile-strict",
				"--proxy-tls-profile=" + profile, "--proxy-tls-profile-strict",
			},
		},
	}
}
