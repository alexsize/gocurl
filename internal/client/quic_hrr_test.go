package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3CapturesHelloRetryRequestClientHellos(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{localTestCertificate(t)},
			CurvePreferences: []tls.CurveID{tls.CurveP384},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = io.WriteString(w, "hrr-ok")
		}),
	}
	defer server.Close()
	go func() { _ = server.Serve(udp) }()

	cfg, err := config.ParseConfig(
		[]string{"--http3", "--insecure", "--json-output", "https://" + udp.LocalAddr().String() + "/hrr"},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	request, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, cfg.RequestURL.String(), nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("observation request failed: %v", err)
	}
	if body, readErr := io.ReadAll(response.Body); readErr != nil || string(body) != "hrr-ok" {
		_ = response.Body.Close()
		t.Fatalf("response body = %q, error = %v", body, readErr)
	}
	_ = response.Body.Close()
	reports, _ := utlsengine.ProfileCheckReports(requestCtx)
	if len(reports) != 2 {
		t.Fatalf("QUIC ClientHello reports = %+v, want initial and post-HRR observations", reports)
	}
	for i, report := range reports {
		if report.HelloIndex != i+1 || report.CaptureStatus != "OBSERVED" || report.Actual == nil ||
			report.Actual.JA4 == "" {
			t.Fatalf("ClientHello report %d = %+v, want indexed OBSERVED fingerprint", i+1, report)
		}
	}
	if reports[0].Actual.NormalizedSHA256 == reports[1].Actual.NormalizedSHA256 {
		t.Fatalf(
			"normalized fingerprints did not reflect distinct ClientHellos: first=%s second=%s",
			reports[0].Actual.NormalizedSHA256,
			reports[1].Actual.NormalizedSHA256,
		)
	}

	assertStrictQUICHRRRejected(ctx, t, cfg, out, &requests)
}

func assertStrictQUICHRRRejected(
	ctx context.Context,
	t *testing.T,
	cfg *config.Config,
	out *output.Output,
	requests *atomic.Int32,
) {
	t.Helper()
	strictCfg := *cfg
	strictCfg.TLSProfileCheck = true
	strictCfg.TLSProfileStrict = true
	strictCfg.TLSProfileDocument = &utlsengine.ClientProfile{
		Expected: utlsengine.ClientProfileExpected{JA4: "not-the-observed-fingerprint"},
	}
	strictTransport, err := NewTransport(&strictCfg, out)
	if err != nil {
		t.Fatal(err)
	}
	strictCtx, _ := utlsengine.NewProfileCheckContext(ctx)
	strictRequest, _ := http.NewRequestWithContext(strictCtx, http.MethodGet, cfg.RequestURL.String(), nil)
	strictResponse, strictErr := strictTransport.RoundTrip(strictRequest)
	if strictResponse != nil {
		_ = strictResponse.Body.Close()
	}
	var profileErr *utlsengine.ProfileCheckError
	if strictErr == nil || !errors.As(strictErr, &profileErr) || profileErr.Status() != "MISMATCH" {
		t.Fatalf("strict HRR request error = %v, want ClientHello MISMATCH", strictErr)
	}
	strictReports, _ := utlsengine.ProfileCheckReports(strictCtx)
	if len(strictReports) != 2 || strictReports[0].CaptureStatus != "MISMATCH" ||
		strictReports[1].CaptureStatus != "MISMATCH" {
		t.Fatalf("strict HRR reports = %+v, want mismatch outcomes for both captured ClientHellos", strictReports)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP/3 server received %d requests after strict mismatch, want only the observation request", got)
	}
}
