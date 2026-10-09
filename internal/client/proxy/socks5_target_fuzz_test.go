package proxy

import (
	"net"
	"strconv"
	"testing"
)

func TestSOCKSUDPRemoteAddressPortBounds(t *testing.T) {
	dial := &socks5Dialer{remoteDNS: true}
	for _, raw := range []string{"127.0.0.1:-1", "[::1]:65536", "target.invalid:99999"} {
		if got, err := dial.socksUDPRemoteAddress(raw); err == nil || got != nil {
			t.Errorf("out-of-range address %q: got=%v, error=%v", raw, got, err)
		}
	}
	for _, port := range []int{0, 1, 65535} {
		got, err := dial.socksUDPRemoteAddress(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil || got.Port != port || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("valid port %d: got=%v, error=%v", port, got, err)
		}
	}
}

func FuzzSOCKSUDPRemoteAddress(f *testing.F) {
	for _, addr := range []string{
		"127.0.0.1:0", "127.0.0.1:65535", "[::1]:443", "target.invalid:443",
		"127.0.0.1:-1", "[::1]:65536", "target.invalid:18446744073709551616",
		"", "[::1", "host:service", "host:\xff", "a\x00b:12",
	} {
		f.Add(addr, true)
		f.Add(addr, false)
	}
	f.Fuzz(func(t *testing.T, addr string, remoteDNS bool) {
		if len(addr) > 8192 {
			t.Skip()
		}
		host, portText, splitErr := net.SplitHostPort(addr)
		port, portErr := strconv.Atoi(portText)
		ip := net.ParseIP(host)
		valid := splitErr == nil && portErr == nil && port >= 0 && port <= 65535 && (ip != nil || remoteDNS)
		dial := &socks5Dialer{remoteDNS: remoteDNS}
		got, err := dial.socksUDPRemoteAddress(addr)
		if (err == nil) != valid || (!valid && got != nil) {
			t.Fatalf("address contract: valid=%t, got=%v, error=%v", valid, got, err)
		}
		if valid && (got.Port != port || !got.IP.Equal(ip)) {
			t.Fatalf("address changed: got=%v, want host=%q port=%d", got, host, port)
		}
	})
}
