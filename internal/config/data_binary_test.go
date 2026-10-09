package config

import (
	"strings"
	"testing"
)

func TestParseConfigAcceptsBinaryFileAndStdinSources(t *testing.T) {
	for _, source := range []string{"@body.bin", "@-"} {
		t.Run(source, func(t *testing.T) {
			cfg, err := ParseConfig([]string{"--data-binary", source, "https://example.test/"})
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}
			if cfg.DataBinary != source {
				t.Fatalf("DataBinary = %q, want %q", cfg.DataBinary, source)
			}
		})
	}
}

func TestParseConfigRejectsInvalidBinaryBodyOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "empty file name",
			args: []string{"--data-binary", "@", "https://example.test/"},
			want: "requires @<file> or @-",
		},
		{
			name: "conflicts with data",
			args: []string{"--data", "a=1", "--data-binary", "@body.bin", "https://example.test/"},
			want: "cannot be used together",
		},
		{
			name: "websocket",
			args: []string{"--data-binary", "@body.bin", "wss://example.test/"},
			want: "not supported for WebSocket",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseConfig() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseConfigWebSocketHTTPVersionCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "ws default", args: []string{"ws://example.test/socket"}},
		{name: "wss explicit HTTP/1.1", args: []string{"--http1.1", "wss://example.test/socket"}},
		{name: "ws HTTP/2", args: []string{"--http2", "ws://example.test/socket"}, wantErr: true},
		{name: "wss HTTP/2", args: []string{"--http2", "wss://example.test/socket"}, wantErr: true},
		{name: "ws HTTP/3", args: []string{"--http3", "ws://example.test/socket"}, wantErr: true},
		{name: "wss HTTP/3", args: []string{"--http3", "wss://example.test/socket"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.args)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "WebSocket requests require HTTP/1.1") {
					t.Fatalf("ParseConfig() error = %v, want explicit WebSocket HTTP/1.1 incompatibility", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}
			if cfg.ForceHTTP2 || cfg.ForceHTTP3 {
				t.Fatalf(
					"HTTP version flags = HTTP/2 %t, HTTP/3 %t; want HTTP/1.1-compatible configuration",
					cfg.ForceHTTP2,
					cfg.ForceHTTP3,
				)
			}
		})
	}
}
