package gocurl

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// boundaryReader detects accidental body consumption during option validation.
type boundaryReader struct{ reads atomic.Int32 }

func (r *boundaryReader) Read([]byte) (int, error) {
	r.reads.Add(1)
	return 0, io.EOF
}

func TestClientDoRejectsInvalidRequestBoundariesBeforeNetwork(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	var tcpCalls, udpCalls atomic.Int32
	tcpDone, udpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			conn, acceptErr := tcp.Accept()
			if acceptErr != nil {
				return
			}
			tcpCalls.Add(1)
			_ = conn.Close()
		}
	}()
	go func() {
		defer close(udpDone)
		var buffer [65535]byte
		for {
			if _, _, readErr := udp.ReadFrom(buffer[:]); readErr != nil {
				return
			}
			udpCalls.Add(1)
		}
	}()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
		<-tcpDone
		<-udpDone
		if tcpCalls.Load() != 0 || udpCalls.Load() != 0 {
			t.Errorf("invalid options reached network: TCP=%d UDP=%d", tcpCalls.Load(), udpCalls.Load())
		}
	})
	for _, tc := range invalidAPIBoundaries() {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.request
			if request.URL == "" {
				address := tcp.Addr().String()
				if request.HTTPVersion == "3" {
					address = udp.LocalAddr().String()
				}
				request.URL = "https://" + address + "/"
			}
			body := &boundaryReader{}
			request.Body = body
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result, doErr := NewClient().Do(ctx, request)
			if result != nil {
				_ = result.Close()
				t.Error("invalid options returned a Result")
			}
			if doErr == nil || !strings.Contains(strings.ToLower(doErr.Error()), strings.ToLower(tc.errorContains)) {
				t.Errorf("error = %v, want validation error containing %q", doErr, tc.errorContains)
			}
			if reads := body.reads.Load(); reads != 0 {
				t.Errorf("body read %d times before validation failed", reads)
			}
		})
	}
}

type apiBoundaryCase struct {
	name          string
	request       Request
	errorContains string
}

func invalidAPIBoundaries() []apiBoundaryCase {
	const profile = "../../internal/client/utlsengine/testdata/profile-v1-valid.json"
	cases := []apiBoundaryCase{
		{"URL", Request{URL: "https://["}, "URL"},
		{"Method", Request{Method: "bad method"}, "method"},
		{"HTTPVersion", Request{HTTPVersion: "4"}, "HTTPVersion"},
		{"TLSMinVersion", Request{TLSMinVersion: "1.1"}, "TLSMinVersion"},
		{"TLSMaxVersion", Request{TLSMaxVersion: "1.4"}, "TLSMaxVersion"},
		{"TLSVersion-order", Request{TLSMinVersion: "1.3", TLSMaxVersion: "1.2"}, "cannot exceed"},
		{"TLSCipherSuites-empty-name", Request{TLSCipherSuites: []string{""}}, "TLSCipherSuites"},
		{"TLSCipherSuites-unknown", Request{TLSCipherSuites: []string{"not-a-cipher"}}, "cipher"},
		{
			"TLSCipherSuites-whitespace",
			Request{TLSCipherSuites: []string{" TLS_RSA_WITH_AES_128_CBC_SHA"}},
			"TLSCipherSuites",
		},
		{"PostQuantum-HTTP3", Request{HTTPVersion: "3", PostQuantum: true}, "post-quantum"},
		{"RequestTarget-form", Request{HTTPVersion: "1.1", RequestTarget: "https://elsewhere.test/"}, "request-target"},
		{"RequestTarget-control", Request{HTTPVersion: "1.1", RequestTarget: "/\r\n"}, "request-target"},
		{"RequestTarget-HTTP2", Request{HTTPVersion: "2", RequestTarget: "/other"}, "request-target"},
		{"NoDefaultHeaders-HTTP2", Request{HTTPVersion: "2", NoDefaultHeaders: true}, "no-default-headers"},
		{"JSONRedactHeaders", Request{JSONRedactHeaders: []string{"bad name"}}, "json-redact-header"},
		{"Header-name", Request{Headers: []Header{{Name: "bad name", Value: "x"}}}, "header"},
		{"Header-value", Request{Headers: []Header{{Name: "X-Test", Value: "x\r\ny"}}}, "header"},
		{"Header-Host", Request{Headers: []Header{{Name: "Host"}}}, "Host"},
		{"ProxyURL", Request{ProxyURL: "https://["}, "proxy URL"},
		{"ProxyInsecure-no-proxy", Request{ProxyInsecure: true}, "proxy-insecure"},
		{"ProxyHTTP2Connect-no-proxy", Request{ProxyHTTP2Connect: true}, "proxy-http2-connect"},
		{"ConnectTimeout-negative", Request{ConnectTimeout: -time.Second}, "ConnectTimeout"},
		{"ConnectTimeout-fractional", Request{ConnectTimeout: time.Millisecond}, "ConnectTimeout"},
		{"ConnectTo", Request{ConnectTo: []string{"not-a-mapping"}}, "connect-to"},
		{"Resolve-empty-host", Request{Resolve: map[string][]string{"": {"127.0.0.1"}}}, "Resolve"},
		{"Resolve-no-address", Request{Resolve: map[string][]string{"test": {}}}, "Resolve"},
		{"Resolve-invalid-IP", Request{Resolve: map[string][]string{"test": {"not-an-ip"}}}, "Resolve"},
		{"IPVersion", Request{IPVersion: "5"}, "IPVersion"},
		{"DNSServers-empty", Request{DNSServers: []string{""}}, "DNSServers"},
		{"DNSServers-whitespace", Request{DNSServers: []string{" 127.0.0.1"}}, "DNSServers"},
		{"ECHConfig", Request{ECHConfig: "not-base64"}, "echconfig"},
		{"ECH-import-conflict", Request{ECH: true, TLSProfile: &TLSProfile{ProfilePath: profile}}, "tls-profile"},
		{
			"ECHGrease-import-conflict",
			Request{ECHGrease: true, TLSProfile: &TLSProfile{ProfilePath: profile}},
			"tls-profile",
		},
		{"OHTTPGatewayURL-alone", Request{OHTTPGatewayURL: "http://127.0.0.1/"}, "OHTTP"},
		{"OHTTPKeysURL-alone", Request{OHTTPKeysURL: "http://127.0.0.1/"}, "OHTTP"},
		{"TLSRandom-short", Request{TLSRandom: make([]byte, 31)}, "TLSRandom"},
		{"TLSRandom-long", Request{TLSRandom: make([]byte, 33)}, "TLSRandom"},
		{"TLSSplitHello-size", Request{TLSSplitHello: &TLSSplitHello{}}, "FirstChunkSize"},
		{
			"TLSSplitHello-negative-delay",
			Request{TLSSplitHello: &TLSSplitHello{FirstChunkSize: 1, Delay: -time.Millisecond}},
			"Delay",
		},
		{
			"TLSSplitHello-fractional-delay",
			Request{TLSSplitHello: &TLSSplitHello{FirstChunkSize: 1, Delay: time.Nanosecond}},
			"Delay",
		},
		{"TLSProfile.Check", Request{TLSProfile: &TLSProfile{Check: true}}, "tls-profile"},
		{"TLSProfile.Strict", Request{TLSProfile: &TLSProfile{Strict: true}}, "tls-profile"},
		{"TLSProfile.ProxyCheck", Request{TLSProfile: &TLSProfile{ProxyCheck: true}}, "proxy-tls-profile"},
		{"TLSProfile.ProxyStrict", Request{TLSProfile: &TLSProfile{ProxyStrict: true}}, "proxy-tls-profile"},
		{
			"TLSProfile.ProxyProfilePath",
			Request{TLSProfile: &TLSProfile{ProxyProfilePath: profile}},
			"proxy-tls-profile",
		},
		{
			"TLSProfile.ProfilePath-HTTP3",
			Request{HTTPVersion: "3", TLSProfile: &TLSProfile{ProfilePath: profile}},
			"HTTP/3",
		},
	}
	cases = append(cases, invalidAPIHTTP2Boundaries()...)
	cases = append(cases, invalidAPIQUICBoundaries()...)
	cases = append(cases, invalidAPIManualTLSBoundaries()...)
	return cases
}

func invalidAPIHTTP2Boundaries() []apiBoundaryCase {
	return []apiBoundaryCase{
		{"HTTP2Settings-without-HTTP2", Request{HTTP2Settings: HTTP2Settings{HeaderTableSize: 1}}, "HTTP/2"},
		{
			"HTTP2Settings.MaxFrameSize-low",
			Request{HTTPVersion: "2", HTTP2Settings: HTTP2Settings{MaxFrameSize: 16383}},
			"max-frame-size",
		},
		{
			"HTTP2Settings.MaxFrameSize-high",
			Request{HTTPVersion: "2", HTTP2Settings: HTTP2Settings{MaxFrameSize: 16777216}},
			"max-frame-size",
		},
		{
			"HTTP2PseudoOrder",
			Request{HTTPVersion: "2", HTTP2PseudoOrder: []string{"method", "path", "authority", "method"}},
			"pseudo-order",
		},
		{"HTTP2SettingsOrder", Request{HTTPVersion: "2", HTTP2SettingsOrder: []string{"UNKNOWN"}}, "settings-order"},
		{
			"HTTP2SettingsOrder-duplicate",
			Request{HTTPVersion: "2", HTTP2SettingsOrder: []string{"ENABLE_PUSH", "ENABLE_PUSH"}},
			"settings-order",
		},
		{"HTTP2DataFrameSize", Request{HTTPVersion: "2", HTTP2DataFrameSize: 16385}, "data-frame-size"},
		{"HTTP2HeaderFrameSize", Request{HTTPVersion: "2", HTTP2HeaderFrameSize: 16385}, "header-frame-size"},
		{
			"HTTP2FramePadding-overhead",
			Request{HTTPVersion: "2", HTTP2HeaderFrameSize: 2, HTTP2FramePadding: 2},
			"overhead",
		},
		{"HTTP2HeaderOrder-invalid", Request{HTTPVersion: "2", HTTP2HeaderOrder: []string{"bad name"}}, "header-order"},
		{
			"HTTP2HeaderOrder-duplicate",
			Request{HTTPVersion: "2", HTTP2HeaderOrder: []string{"x-test", "X-Test"}},
			"header-order",
		},
		{"HTTP2Priority.Weight-low", Request{HTTPVersion: "2", HTTP2Priority: &HTTP2Priority{Weight: 0}}, "weight"},
		{"HTTP2Priority.Weight-high", Request{HTTPVersion: "2", HTTP2Priority: &HTTP2Priority{Weight: 257}}, "weight"},
		{
			"HTTP2Priority.Dependency-self",
			Request{HTTPVersion: "2", HTTP2Priority: &HTTP2Priority{Weight: 16, Dependency: 1}},
			"dependency",
		},
		{
			"HTTP2Priority.Dependency-high",
			Request{HTTPVersion: "2", HTTP2Priority: &HTTP2Priority{Weight: 16, Dependency: 1 << 31}},
			"dependency",
		},
		{
			"HTTP3AdditionalSettings-reserved",
			Request{HTTPVersion: "3", HTTP3AdditionalSettings: map[uint64]uint64{3: 0}},
			"h3-setting",
		},
		{
			"HTTP3AdditionalSettings-ID-overflow",
			Request{HTTPVersion: "3", HTTP3AdditionalSettings: map[uint64]uint64{1 << 62: 1}},
			"h3-setting",
		},
		{
			"HTTP3AdditionalSettings-value-overflow",
			Request{HTTPVersion: "3", HTTP3AdditionalSettings: map[uint64]uint64{64: 1 << 62}},
			"h3-setting",
		},
		{"HTTP3Datagrams-without-HTTP3", Request{HTTP3Datagrams: true}, "h3-datagrams"},
	}
}

func invalidAPIQUICBoundaries() []apiBoundaryCase {
	overflow, exponent := uint64(1<<62), uint8(21)
	negative, fractional, tooLarge := -time.Millisecond, time.Nanosecond, 16384*time.Millisecond
	var cases []apiBoundaryCase
	for _, tc := range []struct {
		name      string
		transport QUICTransport
	}{
		{"InitialStreamReceiveWindow", QUICTransport{InitialStreamReceiveWindow: overflow}},
		{"InitialMaxStreamDataBidiLocal", QUICTransport{InitialMaxStreamDataBidiLocal: &overflow}},
		{"InitialMaxStreamDataBidiRemote", QUICTransport{InitialMaxStreamDataBidiRemote: &overflow}},
		{"InitialMaxStreamDataUni", QUICTransport{InitialMaxStreamDataUni: &overflow}},
		{"InitialConnectionReceiveWindow", QUICTransport{InitialConnectionReceiveWindow: overflow}},
		{"MaxIdleTimeout-negative", QUICTransport{MaxIdleTimeout: -time.Millisecond}},
		{"MaxIdleTimeout-fractional", QUICTransport{MaxIdleTimeout: time.Nanosecond}},
		{"MaxIncomingStreams-negative", QUICTransport{MaxIncomingStreams: -1}},
		{"MaxIncomingStreams-high", QUICTransport{MaxIncomingStreams: 1<<60 + 1}},
		{"MaxIncomingUniStreams-low", QUICTransport{MaxIncomingUniStreams: 2}},
		{"MaxIncomingUniStreams-high", QUICTransport{MaxIncomingUniStreams: 1<<60 + 1}},
		{"Version", QUICTransport{Version: "3"}},
		{"InitialPacketSize-low", QUICTransport{InitialPacketSize: 1199}},
		{"InitialPacketSize-high", QUICTransport{InitialPacketSize: 1453}},
		{"ConnectionIDLength-low", QUICTransport{ConnectionIDLength: -1}},
		{"ConnectionIDLength-high", QUICTransport{ConnectionIDLength: 21}},
		{"ActiveConnectionIDLimit-low", QUICTransport{ActiveConnectionIDLimit: 1}},
		{"ActiveConnectionIDLimit-high", QUICTransport{ActiveConnectionIDLimit: 5}},
		{"AckDelayExponent", QUICTransport{AckDelayExponent: &exponent}},
		{"MaxAckDelay-negative", QUICTransport{MaxAckDelay: &negative}},
		{"MaxAckDelay-fractional", QUICTransport{MaxAckDelay: &fractional}},
		{"MaxAckDelay-high", QUICTransport{MaxAckDelay: &tooLarge}},
		{"MaxUDPPayloadSize-low", QUICTransport{MaxUDPPayloadSize: 1199}},
		{"MaxUDPPayloadSize-high", QUICTransport{MaxUDPPayloadSize: 1453}},
	} {
		cases = append(cases, apiBoundaryCase{
			"QUICTransport." + tc.name,
			Request{HTTPVersion: "3", QUICTransport: tc.transport},
			"QUIC",
		})
	}
	return append(
		cases,
		apiBoundaryCase{
			"QUICTransportParameterOrder-duplicate",
			Request{HTTPVersion: "3", QUICTransportParameterOrder: []uint64{4, 4}},
			"duplicate",
		},
		apiBoundaryCase{
			"QUICTransportParameterOrder-overflow",
			Request{HTTPVersion: "3", QUICTransportParameterOrder: []uint64{1 << 62}},
			"parameter",
		},
	)
}

func invalidAPIManualTLSBoundaries() []apiBoundaryCase {
	var cases []apiBoundaryCase
	for _, tc := range []struct {
		name          string
		profile       TLSClientHello
		errorContains string
	}{
		{"Preset", TLSClientHello{Preset: "unknown-preset"}, "unsupported preset"},
		{"ExtensionOrder-unknown", TLSClientHello{Preset: "chrome-120", ALPN: []string{"http/1.1"}, ExtensionOrder: []uint16{65534}}, "extension order"},
		{"ALPN-incompatible", TLSClientHello{Preset: "chrome-120", ALPN: []string{"h2"}}, "ALPN is incompatible"},
	} {
		cases = append(cases, apiBoundaryCase{"TLSClientHello." + tc.name, Request{
			HTTPVersion: "1.1",
			TLSProfile:  &TLSProfile{ClientHello: &tc.profile},
		}, tc.errorContains})
	}
	return append(cases,
		apiBoundaryCase{"TLSClientHello-SNI-conflict", Request{TLSServerName: "one.test", TLSProfile: &TLSProfile{
			ClientHello: &TLSClientHello{ServerName: "two.test"},
		}}, "conflicts"},
		apiBoundaryCase{"TLSClientHello-import-conflict", Request{TLSProfile: &TLSProfile{
			ProfilePath: "profile.json", ClientHello: &TLSClientHello{},
		}}, "exclusive"},
		apiBoundaryCase{"TLSClientHello-check-conflict", Request{TLSProfile: &TLSProfile{
			Check: true, ClientHello: &TLSClientHello{},
		}}, "Check"},
		apiBoundaryCase{"TLSClientHello-versions-conflict", Request{TLSMinVersion: "1.2", TLSProfile: &TLSProfile{
			ClientHello: &TLSClientHello{},
		}}, "overrides"},
		apiBoundaryCase{"TLSClientHello-HTTP3", Request{HTTPVersion: "3", TLSProfile: &TLSProfile{
			ClientHello: &TLSClientHello{Preset: "chrome-120"},
		}}, "HTTP/3"},
	)
}
