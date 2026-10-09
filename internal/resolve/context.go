package resolve

import (
	"context"
	"net/url"
	"strings"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/miekg/dns"
)

func exchangeDNSContext(ctx context.Context, msg *dns.Msg, u upstream.Upstream) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := u.(interface {
		ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error)
	}); ok {
		return contextual.ExchangeContext(ctx, msg)
	}
	address := u.Address()
	if !strings.Contains(address, "://") {
		address = "udp://" + address
	}
	parsed, err := url.Parse(address)
	if err == nil && (parsed.Scheme == "udp" || parsed.Scheme == "tcp") {
		response, exchangeErr := exchangePlainDNSContext(ctx, msg, parsed.Scheme, parsed.Host)
		if exchangeErr == nil && response != nil && response.Truncated && parsed.Scheme == "udp" {
			return exchangePlainDNSContext(ctx, msg, "tcp", parsed.Host)
		}
		return response, exchangeErr
	}
	// The legacy encrypted upstream keeps its protocol and TLS policy. Its
	// exchange has a finite configured timeout; it never accesses caller logs.
	// Do not close a shared upstream merely to cancel one query.
	type result struct {
		msg *dns.Msg
		err error
	}
	done := make(chan result, 1)
	query := msg.Copy()
	go func() { response, err := u.Exchange(query); done <- result{response, err} }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return result.msg, result.err
	}
}

func exchangePlainDNSContext(ctx context.Context, msg *dns.Msg, network, address string) (*dns.Msg, error) {
	client := &dns.Client{Net: network, Timeout: config.DNSExchangeTimeout}
	conn, err := client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	response, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}
