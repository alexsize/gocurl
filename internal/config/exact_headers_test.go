package config

import (
	"strings"
	"testing"
)

func TestExactHeadersRejectAmbiguousFramingBeforeNetwork(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{"duplicate length", []string{"Content-Length: 3", "content-length: 3"}, "repeated Content-Length"},
		{"invalid length", []string{"Content-Length: -1"}, "invalid Content-Length"},
		{"length and chunked", []string{"Content-Length: 3", "Transfer-Encoding: chunked"}, "conflicts"},
		{"duplicate connection", []string{"Connection: close", "connection: keep-alive"}, "repeated Connection"},
		{"unsupported encoding", []string{"Transfer-Encoding: gzip"}, "only Transfer-Encoding: chunked"},
		{"target proxy authorization", []string{"Proxy-Authorization: Basic dGVzdA=="}, "belongs to the proxy"},
		{"unsupported trailer", []string{"Trailer: X-Final"}, "request Trailer is unsupported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--http1.1", "--no-default-headers"}
			for _, header := range tt.headers {
				args = append(args, "-H", header)
			}
			args = append(args, "http://127.0.0.1:1/")
			_, err := ParseConfig(args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseConfig() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCompatibleHeadersStillAcceptRepeatedConnection(t *testing.T) {
	_, err := ParseConfig(
		[]string{"--http1.1", "-H", "Connection: close", "-H", "Connection: keep-alive", "http://example.test/"},
	)
	if err != nil {
		t.Fatalf("compatible mode changed: %v", err)
	}
}
