package gocurl

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

func TestClientDoQUICSharedAndExplicitZeroWindowsOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()
	zero, override := uint64(0), uint64(333)
	for _, tc := range []struct {
		name      string
		transport QUICTransport
		want      [3]int64
	}{
		{
			name: "shared", transport: QUICTransport{InitialStreamReceiveWindow: 65536},
			want: [3]int64{65536, 65536, 65536},
		},
		{name: "explicit-zero", transport: QUICTransport{
			InitialStreamReceiveWindow:    65536,
			InitialMaxStreamDataBidiLocal: &zero, InitialMaxStreamDataBidiRemote: &zero,
			InitialMaxStreamDataUni: &zero,
		}, want: [3]int64{}},
		{
			name: "mixed", transport: QUICTransport{
				InitialStreamReceiveWindow:    65536,
				InitialMaxStreamDataBidiLocal: &zero, InitialMaxStreamDataUni: &override,
			},
			want: [3]int64{0, 65536, 333},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parameters := make(chan qlog.ParametersSet, 2)
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h3"},
			}, &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &apiQUICTrace{parameters: parameters}
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			serverDone, serverErr := make(chan struct{}), make(chan error, 1)
			accepted := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, acceptErr := listener.Accept(ctx)
				if acceptErr != nil {
					serverErr <- acceptErr
					return
				}
				close(accepted)
				<-ctx.Done()
				serverErr <- conn.CloseWithError(0, "test complete")
			}()
			clientDone := make(chan error, 1)
			go func() {
				result, doErr := NewClient().Do(ctx, Request{
					URL:         "https://" + listener.Addr().String(),
					HTTPVersion: "3", Insecure: true, QUICTransport: tc.transport,
				})
				if result != nil {
					_ = result.Close()
				}
				clientDone <- doErr
			}()
			select {
			case got := <-parameters:
				windows := [3]int64{
					int64(got.InitialMaxStreamDataBidiLocal),
					int64(got.InitialMaxStreamDataBidiRemote), int64(got.InitialMaxStreamDataUni),
				}
				if windows != tc.want {
					t.Errorf("received stream windows = %v, want %v", windows, tc.want)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case <-accepted:
			case acceptErr := <-serverErr:
				t.Fatalf("accept QUIC connection: %v", acceptErr)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			assertAPIQUICShutdown(t, cancel, clientDone, serverDone, serverErr)
		})
	}
}
