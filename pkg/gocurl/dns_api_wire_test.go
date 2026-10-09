package gocurl

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClientDoUsesCustomDNSUpstreamAndIPv6Only(t *testing.T) {
	const hostname = "api-dns6.example.test"
	var aQueries, aaaaQueries atomic.Int32
	dnsPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DNS: %v", err)
	}
	dnsServer := &dns.Server{
		PacketConn: dnsPacketConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(req)
			for _, question := range req.Question {
				switch question.Qtype {
				case dns.TypeA:
					aQueries.Add(1)
				case dns.TypeAAAA:
					aaaaQueries.Add(1)
					response.Answer = append(response.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
						AAAA: net.ParseIP("::1"),
					})
				}
			}
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = dnsServer.Shutdown()
		_ = dnsPacketConn.Close()
	})

	ipv6Listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns6" {
			t.Errorf("request path = %q, want /dns6", r.URL.Path)
		}
		_, _ = io.WriteString(w, "custom IPv6 DNS route ok")
	}))
	_ = server.Listener.Close()
	server.Listener = ipv6Listener
	server.Start()
	defer server.Close()
	probeConn, err := net.DialTimeout("tcp6", server.Listener.Addr().String(), 500*time.Millisecond)
	if err != nil {
		t.Skipf("IPv6 loopback connections are restricted in this environment: %v", err)
	}
	_ = probeConn.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(server address): %v", err)
	}
	result, err := NewClient().Do(context.Background(), Request{
		URL:        "http://" + net.JoinHostPort(hostname, port) + "/dns6",
		IPVersion:  "6",
		DNSServers: []string{dnsPacketConn.LocalAddr().String()},
	})
	if err != nil {
		t.Fatalf("Do() with custom DNS and IPv6-only resolution: %v", err)
	}
	defer result.Close()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "custom IPv6 DNS route ok" {
		t.Fatalf("response = %d %q, want 200 with custom IPv6 DNS response", result.Response.StatusCode, body)
	}
	if aQueries.Load() != 0 || aaaaQueries.Load() == 0 {
		t.Errorf("custom DNS query counts: A=%d AAAA=%d; want A=0 and AAAA>0", aQueries.Load(), aaaaQueries.Load())
	}
}
