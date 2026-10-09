package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

func (d *socks5Dialer) resolveSOCKS5Target(ctx context.Context, network, addr string) (string, error) {
	if !d.remoteDNS && (network == "tcp" || network == "udp") {
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return addr, splitErr
		}
		if net.ParseIP(host) == nil {
			ips, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if lookupErr != nil {
				return addr, lookupErr
			}
			if len(ips) == 0 {
				return addr, fmt.Errorf("resolve SOCKS5 target %q: no IP addresses", host)
			}
			addr = net.JoinHostPort(ips[0].String(), port)
		}
	}

	return addr, nil
}

func (d *socks5Dialer) socksUDPRemoteAddress(addr string) (*net.UDPAddr, error) {
	host, portText, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, splitErr
	}
	port, parseErr := strconv.Atoi(portText)
	if parseErr != nil {
		return nil, fmt.Errorf("invalid SOCKS5 UDP target port %q: %w", portText, parseErr)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid SOCKS5 UDP target port %q: must be 0..65535", portText)
	}
	remoteAddr := &net.UDPAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		remoteAddr.IP = ip
	} else if !d.remoteDNS {
		return nil, fmt.Errorf("SOCKS5 target %q was not resolved locally", host)
	}
	return remoteAddr, nil
}
