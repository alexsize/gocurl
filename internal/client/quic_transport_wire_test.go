package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type transportParameterTrace struct {
	observed   chan qlog.ParametersSet
	packetSize chan int
	cidLength  chan int
}

func (t *transportParameterTrace) AddProducer() qlogwriter.Recorder {
	return &transportParameterRecorder{observed: t.observed, packetSize: t.packetSize, cidLength: t.cidLength}
}

func (*transportParameterTrace) SupportsSchemas(string) bool { return true }

type transportParameterRecorder struct {
	observed   chan qlog.ParametersSet
	packetSize chan int
	cidLength  chan int
}

func (r *transportParameterRecorder) RecordEvent(event qlogwriter.Event) {
	if parameters, ok := event.(qlog.ParametersSet); ok && parameters.Initiator == qlog.InitiatorRemote {
		select {
		case r.observed <- parameters:
		default:
		}
	}
	if packet, ok := event.(qlog.PacketReceived); ok && packet.Header.PacketType == qlog.PacketTypeInitial {
		select {
		case r.packetSize <- packet.Raw.Length:
		default:
		}
		select {
		case r.cidLength <- packet.Header.SrcConnectionID.Len():
		default:
		}
	}
}

func (*transportParameterRecorder) Close() error { return nil }

func TestQUICTransportParametersOnWire(t *testing.T) {
	observed := make(chan qlog.ParametersSet, 2)
	packetSizes := make(chan int, 4)
	cidLengths := make(chan int, 4)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h3"},
	}, &quic.Config{Versions: []quic.Version{quic.Version2}, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &transportParameterTrace{observed: observed, packetSize: packetSizes, cidLength: cidLengths}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	negotiated := make(chan quic.Version, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		negotiated <- conn.ConnectionState().Version
		<-ctx.Done()
		serverDone <- conn.CloseWithError(0, "test done")
	}()

	cfg, err := config.ParseConfig([]string{
		"--http3",
		"--insecure",
		"--h3-datagrams",
		"--quic-initial-stream-window=65536",
		"--quic-initial-connection-window=262144",
		"--quic-max-idle-timeout-ms=7000",
		"--quic-max-incoming-streams=10",
		"--quic-max-incoming-uni-streams=12",
		"--quic-version=2",
		"--quic-initial-packet-size=1300",
		"--quic-connection-id-length=8",
		"--quic-initial-max-stream-data-bidi-local=111",
		"--quic-initial-max-stream-data-bidi-remote=222",
		"--quic-initial-max-stream-data-uni=333",
		"--quic-active-connection-id-limit=4",
		"--quic-ack-delay-exponent=0",
		"--quic-max-ack-delay-ms=0",
		"--quic-max-udp-payload-size=1350",
		"--quic-reset-stream-at",
		"--quic-disable-active-migration",
		"--quic-transport-parameter-order=0x4,0x1,0x5",
		"https://" + listener.Addr().String() + "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RequestURL.String(), nil)
	clientDone := make(chan struct{}, 1)
	go func() {
		if resp, roundErr := transport.RoundTrip(req); roundErr == nil {
			_ = resp.Body.Close()
		}
		clientDone <- struct{}{}
	}()

	assertQUICTransportParameterObservation(ctx, t, observed, serverDone)
	select {
	case size := <-packetSizes:
		if size != 1300 {
			t.Fatalf("received QUIC Initial datagram size = %d, want 1300", size)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case length := <-cidLengths:
		if length != 8 {
			t.Fatalf("received QUIC source connection ID length = %d, want 8", length)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case version := <-negotiated:
		if version != quic.Version2 {
			t.Fatalf("negotiated QUIC version = %v, want v2", version)
		}
	case err := <-serverDone:
		t.Fatalf("server ended before version check: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client request did not stop after cancellation")
	}
}

func TestHTTP3WithCustomQUICTransportGetsResponse(t *testing.T) {
	var receivedRequests atomic.Int32
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}},
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedRequests.Add(1)
			if r.ProtoMajor != 3 || r.URL.Path != "/custom" {
				t.Errorf("request = %s %s", r.Proto, r.URL.Path)
			}
			_, _ = io.WriteString(w, "custom-quic-ok")
		}),
	}
	defer server.Close()
	go func() { _ = server.Serve(udp) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := config.ParseConfig([]string{
		"--http3",
		"--insecure",
		"--h3-datagrams",
		"--json-output",
		"--quic-version=2",
		"--quic-initial-stream-window=65536",
		"--quic-initial-connection-window=262144",
		"--quic-max-idle-timeout-ms=7000",
		"--quic-max-incoming-streams=10",
		"--quic-initial-packet-size=1300",
		"--quic-connection-id-length=8",
		"--quic-max-incoming-uni-streams=12",
		"--h3-setting=0x40=127",
		"https://" + udp.LocalAddr().String() + "/custom",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	req, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, cfg.RequestURL.String(), nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.ProtoMajor != 3 || string(body) != "custom-quic-ok" {
		t.Fatalf("response = %s, body = %q, error = %v", resp.Proto, body, err)
	}
	reports, _ := utlsengine.ProfileCheckReports(requestCtx)
	if len(reports) != 1 || reports[0].CaptureStatus != "OBSERVED" || reports[0].Actual == nil ||
		reports[0].Actual.JA3 == "" || reports[0].Actual.JA4 == "" || len(reports[0].Actual.ALPN) == 0 ||
		reports[0].Actual.ALPN[0] != "h3" {
		t.Fatalf("QUIC ClientHello report = %+v, want one observed fingerprint with h3 ALPN", reports)
	}

	assertCustomQUICStrictProfiles(ctx, t, cfg, out, reports[0].Actual.JA4, &receivedRequests)
}

func assertQUICTransportParameterObservation(
	ctx context.Context,
	t *testing.T,
	observed <-chan qlog.ParametersSet,
	serverDone <-chan error,
) {
	t.Helper()
	select {
	case got := <-observed:
		if got.InitialMaxStreamDataBidiLocal != 111 ||
			got.InitialMaxStreamDataBidiRemote != 222 ||
			got.InitialMaxStreamDataUni != 333 ||
			got.InitialMaxData != 262144 ||
			got.MaxIdleTimeout != 7*time.Second ||
			got.InitialMaxStreamsBidi != 10 || got.InitialMaxStreamsUni != 12 ||
			got.MaxDatagramFrameSize <= 0 || got.ActiveConnectionIDLimit != 4 || got.AckDelayExponent != 0 || got.MaxAckDelay != 0 || got.MaxUDPPayloadSize != 1350 || !got.EnableResetStreamAt || !got.DisableActiveMigration {
			t.Fatalf("received client QUIC transport parameters = %+v", got)
		}
	case err := <-serverDone:
		t.Fatalf("server ended before receiving transport parameters: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func assertCustomQUICStrictProfiles(
	ctx context.Context,
	t *testing.T,
	cfg *config.Config,
	out *output.Output,
	expectedJA4 string,
	receivedRequests *atomic.Int32,
) {
	t.Helper()
	strictCfg := *cfg
	strictCfg.TLSProfileCheck = true
	strictCfg.TLSProfileStrict = true
	strictCfg.TLSProfileDocument = &utlsengine.ClientProfile{
		Expected: utlsengine.ClientProfileExpected{JA4: expectedJA4},
	}
	matchingTransport, err := NewTransport(&strictCfg, out)
	if err != nil {
		t.Fatalf("NewTransport(matching strict profile) error = %v", err)
	}
	matchingCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	matchingReq, _ := http.NewRequestWithContext(matchingCtx, http.MethodGet, cfg.RequestURL.String(), nil)
	matchingResp, err := matchingTransport.RoundTrip(matchingReq)
	if err != nil {
		t.Fatalf("strict HTTP/3 request with matching QUIC profile failed: %v", err)
	}
	_ = matchingResp.Body.Close()
	matchingReports, _ := utlsengine.ProfileCheckReports(matchingCtx)
	if len(matchingReports) != 1 || matchingReports[0].CaptureStatus != "MATCH" || matchingReports[0].Actual == nil {
		t.Fatalf("matching strict QUIC ClientHello report = %+v, want MATCH with actual fingerprint", matchingReports)
	}

	strictCfg.TLSProfileDocument = &utlsengine.ClientProfile{
		Expected: utlsengine.ClientProfileExpected{JA4: "not-the-observed-fingerprint"},
	}
	assertReusedQUICProfileRejected(ctx, t, cfg.RequestURL.String(), matchingTransport, receivedRequests)

	strictTransport, err := NewTransport(&strictCfg, out)
	if err != nil {
		t.Fatalf("NewTransport(strict) error = %v", err)
	}
	strictCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	strictReq, _ := http.NewRequestWithContext(strictCtx, http.MethodGet, cfg.RequestURL.String(), nil)
	strictResp, strictErr := strictTransport.RoundTrip(strictReq)
	if strictResp != nil {
		_ = strictResp.Body.Close()
	}
	if strictErr == nil || !strings.Contains(strictErr.Error(), "strict TLS profile check failed: MISMATCH") {
		t.Fatalf("strict HTTP/3 request error = %v, want a QUIC ClientHello MISMATCH", strictErr)
	}
	if got := receivedRequests.Load(); got != 2 {
		t.Fatalf(
			"HTTP/3 server received %d requests after strict rejection, want the initial and matching-profile requests",
			got,
		)
	}
	strictReports, _ := utlsengine.ProfileCheckReports(strictReq.Context())
	if len(strictReports) != 1 || strictReports[0].CaptureStatus != "MISMATCH" || strictReports[0].Actual == nil {
		t.Fatalf("strict QUIC ClientHello report = %+v, want observed MISMATCH", strictReports)
	}
}

func assertReusedQUICProfileRejected(
	ctx context.Context,
	t *testing.T,
	requestURL string,
	matchingTransport Transport,
	receivedRequests *atomic.Int32,
) {
	t.Helper()
	reusedCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	reusedReq, _ := http.NewRequestWithContext(reusedCtx, http.MethodGet, requestURL, nil)
	reusedResp, reusedErr := matchingTransport.RoundTrip(reusedReq)
	if reusedResp != nil {
		_ = reusedResp.Body.Close()
	}
	if reusedErr == nil || !strings.Contains(reusedErr.Error(), "REUSED_CONNECTION") {
		t.Fatalf("second strict HTTP/3 request error = %v, want strict REUSED_CONNECTION rejection", reusedErr)
	}
	if got := receivedRequests.Load(); got != 2 {
		t.Fatalf(
			"HTTP/3 server received %d requests after second strict rejection, want only initial and first matching requests",
			got,
		)
	}
	reusedReports, _ := utlsengine.ProfileCheckReports(reusedCtx)
	if len(reusedReports) != 1 || reusedReports[0].CaptureStatus != "REUSED_CONNECTION" ||
		reusedReports[0].Actual != nil {
		t.Fatalf(
			"second strict QUIC ClientHello report = %+v, want REUSED_CONNECTION without a fabricated new fingerprint",
			reusedReports,
		)
	}
}
