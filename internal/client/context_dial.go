package client

import (
	"context"
	"net"
)

func (d *clientDialer) openConnection(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.dialContext != nil {
		return d.dialContext(ctx, network, addr)
	}
	// Keep compatibility with test and external legacy dial functions. All
	// production chains constructed by createDialFunc use the contextual path.
	return d.dial(network, addr)
}
