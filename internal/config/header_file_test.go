package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfigHeaderFilePrecedesCLIHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.txt")
	if err := os.WriteFile(path, []byte("X-First: one\r\n\r\nX-Repeat: file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseConfig(
		[]string{"--header-file", path, "-H", "X-Repeat: cli", "-H", "X-Last: three", "https://example.test"},
	)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	want := []string{"X-First: one", "X-Repeat: file", "X-Repeat: cli", "X-Last: three"}
	if !reflect.DeepEqual(cfg.OrderedHeaders, want) {
		t.Fatalf("OrderedHeaders = %#v, want %#v", cfg.OrderedHeaders, want)
	}
	if got := cfg.Headers.Values("X-Repeat"); !reflect.DeepEqual(got, []string{" file", " cli"}) {
		t.Fatalf("Headers[X-Repeat] = %#v, want both file and CLI values", got)
	}
}

func TestParseConfigRejectsInvalidHeaderFileLineWithNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.txt")
	if err := os.WriteFile(path, []byte("X-Good: yes\ninvalid header\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ParseConfig([]string{"--header-file", path, "https://example.test"})
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("ParseConfig() error = %v, want line 2 validation error", err)
	}
}

func TestReadHeaderFileRejectsInvalidUTF8AndFieldSyntax(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "invalid utf8", data: []byte{0xff}},
		{name: "invalid name", data: []byte("Bad Name: value\n")},
		{name: "missing colon", data: []byte("BadHeader\n")},
		{name: "embedded carriage return", data: []byte("X-Test: a\rb\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "headers.txt")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readHeaderFile(path); err == nil {
				t.Fatal("readHeaderFile() unexpectedly succeeded")
			}
		})
	}
}

func FuzzReadHeaderFile(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("X-Test: value\r\nX-Repeat: one\nX-Repeat: two\n"),
		[]byte(""),
		{0xff, 0xfe},
		[]byte("X-Test: a\rInjected: b\n"),
		[]byte("MissingColon\n"),
	} {
		f.Add(seed)
	}

	path := filepath.Join(f.TempDir(), "headers.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write fuzz header file: %v", err)
		}
		headers, err := readHeaderFile(path)
		if err != nil {
			return
		}
		for i, header := range headers {
			colon := strings.IndexByte(header, ':')
			if colon <= 0 || !validHeaderFieldName(header[:colon]) ||
				strings.ContainsAny(header[colon+1:], "\r\n\x00") {
				t.Fatalf("readHeaderFile() header[%d] = %q, contains invalid field syntax", i, header)
			}
		}
	})
}

func TestParseConfigRejectsInvalidCLIHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{name: "missing colon", headers: []string{"X-Test"}},
		{name: "invalid name", headers: []string{"Bad Name: value"}},
		{name: "injected newline", headers: []string{"X-Test: value\r\nX-Injected: yes"}},
		{name: "duplicate Host", headers: []string{"Host: first.test", "host: second.test"}},
		{name: "empty Host", headers: []string{"Host:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := make([]string, 0, len(tt.headers)*2+1)
			for _, header := range tt.headers {
				args = append(args, "-H", header)
			}
			args = append(args, "http://127.0.0.1:1/")
			if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--header entry") {
				t.Fatalf("ParseConfig(%q) error = %v, want invalid --header entry", tt.headers, err)
			}
		})
	}
}

func TestParseConfigRequestTargetRequiresHTTP11OriginForm(t *testing.T) {
	for _, args := range [][]string{
		{"--request-target=/wire", "http://example.test/original"},
		{"--http1.1", "--request-target=relative", "http://example.test/original"},
		{"--http1.1", "--request-target=/bad\r\nX-Injected: yes", "http://example.test/original"},
		{"--http1.1", "--request-target=/bad#fragment", "http://example.test/original"},
		{"--http1.1", "--request-target=/wire", "ws://example.test/original"},
		{"--http1.1", "--request-target=/wire", "--proxy", "http://proxy.test", "http://example.test/original"},
	} {
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--request-target") {
			t.Fatalf("ParseConfig(%q) error = %v, want request-target incompatibility", args, err)
		}
	}
}

func TestParseConfigNoDefaultHeadersRequiresHTTP11(t *testing.T) {
	if _, err := ParseConfig(
		[]string{"--no-default-headers", "http://example.test/"},
	); err == nil ||
		!strings.Contains(err.Error(), "--no-default-headers requires --http1.1") {
		t.Fatalf("ParseConfig() error = %v, want HTTP/1.1 requirement", err)
	}
	if _, err := ParseConfig(
		[]string{"--http1.1", "--no-default-headers", "ws://example.test/"},
	); err == nil ||
		!strings.Contains(err.Error(), "unsupported for WebSocket") {
		t.Fatalf("ParseConfig(WebSocket) error = %v, want mode incompatibility", err)
	}
}
