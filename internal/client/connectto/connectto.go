// Package connectto implements the --connect-to command-line argument logic
// that allows "redirecting" connections to hosts.
package connectto

import (
	"context"
	"net"

	"github.com/ameshkov/gocurl/internal/client/dialer"
	"github.com/ameshkov/gocurl/internal/output"
)

// CreateContextDialFunc redirects connections without losing cancellation.
func CreateContextDialFunc(
	connectTo map[string]string,
	base dialer.ContextDialFunc,
	out *output.Output,
) dialer.ContextDialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if target, ok := connectTo[addr]; ok {
			out.Debug("Redirecting %s to %s", addr, target)
			addr = target
		}
		return base(ctx, network, addr)
	}
}

// CreateDialFunc creates a dialer.DialFunc that overrides the remote endpoint
// if the address matches what an entry in the connectTo map.
func CreateDialFunc(
	connectTo map[string]string,
	baseDial dialer.DialFunc,
	out *output.Output,
) (f dialer.DialFunc, err error) {
	out.Debug("Some connections will be redirected due to --connect-to")

	return func(network, addr string) (net.Conn, error) {
		if v, ok := connectTo[addr]; ok {
			out.Debug("Redirecting %s to %s", addr, v)
			addr = v
		}

		return baseDial(network, addr)
	}, nil
}
