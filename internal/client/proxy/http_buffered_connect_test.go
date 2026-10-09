package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
)

func TestHTTPConnectPreservesCoalescedTunnelBytes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			const greeting = "\x16\x03\x03tunnel-first-bytes"
			serverErrors := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					http.Error(w, "expected CONNECT", http.StatusBadRequest)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					serverErrors <- err
					return
				}
				defer conn.Close()
				_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"+greeting)
				serverErrors <- err
			})
			var server *httptest.Server
			if secure {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			d, err := createHTTPProxyDialer(
				u,
				fixedDialer{address: server.Listener.Addr().String()},
				time.Second,
				TLSProfileOptions{InsecureSkipVerify: true},
			)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.(*httpProxyDialer).DialContext(context.Background(), "tcp", "target.test:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			data := make([]byte, len(greeting))
			if _, err = io.ReadFull(conn, data); err != nil || string(data) != greeting {
				t.Fatalf("first tunnel bytes = %q, %v; want %q", data, err, greeting)
			}
			if secure {
				provider, ok := conn.(interface {
					ProxyTLSObservations() []utlsengine.ProfileCheckResult
				})
				if !ok || len(provider.ProxyTLSObservations()) != 1 ||
					provider.ProxyTLSObservations()[0].Status != "OBSERVED" {
					t.Fatalf("buffered HTTPS tunnel lost its proxy TLS observation: %T", conn)
				}
			}
			if err = <-serverErrors; err != nil && !strings.Contains(err.Error(), "closed") {
				t.Fatal(err)
			}
		})
	}
}
