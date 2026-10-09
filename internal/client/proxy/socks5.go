package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/ameshkov/gocurl/internal/client/dialer"
	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

// defaultSocksTimeout is the default timeout to use for connecting to the socks proxy.
const defaultSocksTimeout int = 60

// socks5Dialer is a wrapper over socks5.Client that adds support for proxying
// UDP over SOCKS5.
type socks5Dialer struct {
	client    *socks5.Client
	remoteDNS bool
}

// type check
var _ proxy.Dialer = (*socks5Dialer)(nil)

// socksConn is a wrapper over socks5.Client that implements net.PacketConn
// in addition to net.Conn.
type socksConn struct {
	*socks5.Client
}

// type check
var _ net.PacketConn = (*socksConn)(nil)

// ReadFrom implements net.PacketConn for *socksConn.
func (s *socksConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = s.Read(p)

	return n, s.RemoteAddr(), err
}

// WriteTo implements net.PacketConn for *socksConn.
func (s *socksConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return s.Write(p)
}

func (s *socksConn) SetReadBuffer(size int) error {
	conn, ok := s.UDPConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return fmt.Errorf("SOCKS5 UDP relay does not support setting the read buffer")
	}
	return conn.SetReadBuffer(size)
}

func (s *socksConn) SetWriteBuffer(size int) error {
	conn, ok := s.UDPConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return fmt.Errorf("SOCKS5 UDP relay does not support setting the write buffer")
	}
	return conn.SetWriteBuffer(size)
}

// Dial implements the proxy.Dialer interface for *socks5Dialer.
func (d *socks5Dialer) Dial(network, addr string) (conn net.Conn, err error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext cancels SOCKS negotiation and owns every socket opened for it.
func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	clientConfig := *d.client
	timeout := time.Duration(clientConfig.TCPTimeout) * time.Second
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	var opened []net.Conn
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil {
			for _, socket := range opened {
				if err = socket.SetDeadline(time.Time{}); err != nil {
					break
				}
			}
		}
		if err != nil {
			for _, socket := range opened {
				_ = socket.Close()
			}
			conn = nil
		}
	}()
	open := func(network, _, remote string) (net.Conn, error) {
		socket, dialErr := (&net.Dialer{}).DialContext(ctx, network, remote)
		if dialErr != nil {
			return nil, dialErr
		}
		opened = append(opened, socket)
		stops = append(stops, dialer.WatchContext(ctx, socket))
		return socket, nil
	}
	clientConfig.DialTCP, clientConfig.DialUDP = open, open
	addr, err = d.resolveSOCKS5Target(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conn, err = clientConfig.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	client := conn.(*socks5.Client)
	if network == "udp" {
		client.RemoteAddress, err = d.socksUDPRemoteAddress(addr)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return &socksConn{Client: client}, nil
}

// createSOCKS5ProxyDialer creates a proxy.Dialer that connects to a SOCKS5
// proxy. The difference with the built-in proxy support is that it supports
// proxying UDP traffic. connectTimeoutSecs is the timeout in seconds for
// connecting to the proxy. If 0, uses the default timeout.
func createSOCKS5ProxyDialer(u *url.URL, connectTimeoutSecs int) (d proxy.Dialer, err error) {
	var addr, username, password string

	if u.User != nil {
		username = u.User.Username()
		if p, ok := u.User.Password(); ok {
			password = p
		}
	}

	port := "1080"
	if u.Port() != "" {
		port = u.Port()
	}
	addr = net.JoinHostPort(u.Hostname(), port)

	timeout := connectTimeoutSecs
	if timeout == 0 {
		timeout = defaultSocksTimeout
	}

	client, err := socks5.NewClient(addr, username, password, timeout, timeout)
	if err != nil {
		return nil, err
	}

	return &socks5Dialer{client: client, remoteDNS: u.Scheme == "socks5h"}, err
}
