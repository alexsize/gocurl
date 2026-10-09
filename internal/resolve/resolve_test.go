package resolve_test

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	ctls "github.com/ameshkov/cfcrypto/tls"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/ameshkov/gocurl/internal/resolve"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestResolver_LookupHost(t *testing.T) {
	r := newLocalResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, question := range req.Question {
			switch question.Qtype {
			case dns.TypeA:
				resp.Answer = append(
					resp.Answer,
					&dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
						A:   net.IPv4(192, 0, 2, 10),
					},
				)
			case dns.TypeAAAA:
				resp.Answer = append(
					resp.Answer,
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
						AAAA: net.ParseIP("2001:db8::10"),
					},
				)
			}
		}
		_ = w.WriteMsg(resp)
	})

	addrs, err := r.LookupHost("www.example.org")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.IPv4(192, 0, 2, 10).To4(), net.ParseIP("2001:db8::10")}, addrs)
}

func TestResolver_LookupHost_customServers(t *testing.T) {
	r := newLocalResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   net.IPv4(198, 51, 100, 7),
				},
			}
		}
		_ = w.WriteMsg(resp)
	})

	addrs, err := r.LookupHost("www.example.org")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.IPv4(198, 51, 100, 7).To4()}, addrs)
}

func TestResolver_LookupHost_ipAddr(t *testing.T) {
	r := newLocalResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	})

	addrs, err := r.LookupHost("127.0.0.1")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)
	require.Equal(t, []net.IP{{127, 0, 0, 1}}, addrs)
}

func TestResolver_LookupHost_preConfigured(t *testing.T) {
	cfg := &config.Config{
		Resolve: map[string][]net.IP{
			"example.org": {{127, 0, 0, 1}},
			"*":           {{127, 0, 0, 2}},
		},
	}
	r := newLocalResolverWithConfig(t, cfg)

	addrs, err := r.LookupHost("example.org")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)
	require.Equal(t, []net.IP{{127, 0, 0, 1}}, addrs)

	addrs, err = r.LookupHost("example.net")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)
	require.Equal(t, []net.IP{{127, 0, 0, 2}}, addrs)
}

func TestResolver_LookupECHConfigs(t *testing.T) {
	echBytes := testECHConfigBytes(t)
	r := newLocalResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 1},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: echBytes}},
		}}}
		_ = w.WriteMsg(resp)
	})

	echConfigs, err := r.LookupECHConfigs("example.test")
	require.NoError(t, err)
	require.NotEmpty(t, echConfigs)
	require.Equal(t, testECHConfigs(t), echConfigs)
}

func TestResolver_LookupECHConfigs_preConfigured(t *testing.T) {
	configuredECHConfigs := testECHConfigs(t)
	cfg := &config.Config{ECHConfigs: configuredECHConfigs}
	r := newLocalResolverWithConfig(t, cfg)

	echConfigs, err := r.LookupECHConfigs("crypto.cloudflare.com")
	require.NoError(t, err)
	require.NotEmpty(t, echConfigs)
	require.Equal(t, configuredECHConfigs, echConfigs)
}

func TestResolver_LookupECHConfigs_empty(t *testing.T) {
	r := newLocalResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	})

	echConfigs, err := r.LookupECHConfigs("example.org")
	require.ErrorIs(t, err, resolve.ErrEmptyResponse)
	require.Empty(t, echConfigs)
}

func newLocalResolver(t *testing.T, handler func(dns.ResponseWriter, *dns.Msg)) *resolve.Resolver {
	t.Helper()
	return newLocalResolverWithConfig(t, &config.Config{}, handler)
}

func newLocalResolverWithConfig(
	t *testing.T,
	cfg *config.Config,
	handlers ...func(dns.ResponseWriter, *dns.Msg),
) *resolve.Resolver {
	t.Helper()
	var handler dns.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	})
	if len(handlers) > 0 {
		handler = dns.HandlerFunc(handlers[0])
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	u, err := upstream.AddressToUpstream(packetConn.LocalAddr().String(), nil)
	require.NoError(t, err)
	cfg.DNSServers = []upstream.Upstream{u}
	out, err := output.NewOutput("", false, false)
	require.NoError(t, err)
	r, err := resolve.NewResolver(cfg, out)
	require.NoError(t, err)
	return r
}

func testECHConfigBytes(t *testing.T) []byte {
	t.Helper()
	const encoded = "AEX+DQBBowAgACA+MDtQ9ShQuke+cqO01oHPiKeg1UDwoyeh5EL+9wfWQwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
	data, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return data
}

func testECHConfigs(t *testing.T) []ctls.ECHConfig {
	t.Helper()
	configs, err := ctls.UnmarshalECHConfigs(testECHConfigBytes(t))
	require.NoError(t, err)
	require.NotEmpty(t, configs)
	return configs
}
