package gocurl

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClientDoDiscoversAndAcceptsECHFromLocalDNS(t *testing.T) {
	encoded, provider := makeLocalECHConfigForPublicAPI(t)
	echConfig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "private.ech.example.test"
	serverResult := make(chan apiECHServerResult, 1)
	go serveAPIAcceptedECH(listener, provider, serverResult)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var httpsQueries atomic.Int32
	ready, done := make(chan struct{}), make(chan error, 1)
	dnsServer := &dns.Server{
		PacketConn: packet, NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			for _, question := range request.Question {
				if question.Qtype == dns.TypeHTTPS && question.Name == dns.Fqdn(hostname) {
					httpsQueries.Add(1)
					response.Answer = append(response.Answer, &dns.HTTPS{SVCB: dns.SVCB{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeHTTPS,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Priority: 1,
						Target:   ".",
						Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: echConfig}},
					}})
				}
			}
			_ = w.WriteMsg(response)
		}),
	}
	go func() { done <- dnsServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = dnsServer.Shutdown()
		_ = packet.Close()
		if serveErr := <-done; serveErr != nil {
			t.Errorf("local DNS server: %v", serveErr)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	address := net.JoinHostPort(hostname, port)
	result, err := NewClient().Do(ctx, Request{
		URL: "https://" + address + "/ech-api", ECH: true, Insecure: true,
		Resolve: map[string][]string{hostname: {"127.0.0.1"}}, DNSServers: []string{packet.LocalAddr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "ech-accepted" {
		t.Fatalf("ECH HTTP result = %d %q", result.Response.StatusCode, body)
	}
	assertAPIAcceptedECH(ctx, t, "local DNS discovery", address, serverResult)
	if httpsQueries.Load() == 0 {
		t.Error("ECH flag did not discover ECHConfig via DNS HTTPS query")
	}
}
