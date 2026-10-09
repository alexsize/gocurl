package config

import (
	"strings"
	"testing"
)

func TestParseHTTPSettings(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--http2", "--h2-header-table-size=8192", "--h2-max-frame-size=32768",
		"--h2-max-header-list-size=65536", "https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.HTTP2Settings; got != (HTTP2Settings{8192, 32768, 65536}) {
		t.Fatalf("HTTP2Settings = %+v", got)
	}

	cfg, err = ParseConfig([]string{"--http3", "--h3-setting=0x40=0x7f", "--h3-setting=65=0", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.HTTP3AdditionalSettings) != 2 || cfg.HTTP3AdditionalSettings[64] != 127 ||
		cfg.HTTP3AdditionalSettings[65] != 0 {
		t.Fatalf("HTTP3AdditionalSettings = %+v", cfg.HTTP3AdditionalSettings)
	}
}

func TestParseHTTPSettingsRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--h2-max-frame-size=32768"}, "require --http2"},
		{[]string{"--http2", "--h2-max-frame-size=16383"}, "16384..16777215"},
		{[]string{"--http2", "--h2-max-frame-size=16777216"}, "16384..16777215"},
		{[]string{"--http2", "--h2-max-frame-size=0"}, "16384..16777215"},
		{[]string{"--http2", "--h2-header-table-size=0"}, "1..4294967295"},
		{[]string{"--http3", "--h3-setting=6=1"}, "standard or reserved"},
		{[]string{"--http3", "--h3-setting=0x33=1"}, "standard or reserved"},
		{[]string{"--http3", "--h3-setting=64=1", "--h3-setting=0x40=2"}, "duplicate"},
		{[]string{"--http3", "--h3-setting=bad"}, "expected ID=VALUE"},
		{[]string{"--http3", "--h3-setting=64=18446744073709551615"}, "invalid VALUE"},
		{[]string{"--h3-setting=64=1"}, "requires --http3"},
	} {
		args := append(append([]string{}, tc.args...), "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseConfig(%q) error = %v, want %q", args, err, tc.want)
		}
	}
}

func TestParseJSONRedactHeaders(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--json-output", "--json-redact-header=Authorization", "--json-redact-header", "X-Secret",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.JSONRedactHeaders) != 2 || cfg.JSONRedactHeaders[0] != "Authorization" ||
		cfg.JSONRedactHeaders[1] != "X-Secret" {
		t.Fatalf("JSONRedactHeaders = %#v", cfg.JSONRedactHeaders)
	}
	if _, err = ParseConfig([]string{"--json-redact-header=Bad Header", "https://example.test/"}); err == nil {
		t.Fatal("expected an invalid header name to be rejected")
	}
}

func TestParseProxyHTTP2Connect(t *testing.T) {
	cfg, err := ParseConfig([]string{
		"--proxy=https://proxy.example.test", "--proxy-http2-connect", "https://target.example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProxyHTTP2Connect {
		t.Fatal("ProxyHTTP2Connect = false, want true")
	}
	for _, args := range [][]string{
		{"--proxy-http2-connect", "https://target.example.test/"},
		{"--proxy=http://proxy.example.test", "--proxy-http2-connect", "https://target.example.test/"},
		{"--proxy=https://proxy.example.test", "--proxy-http2-connect", "--http3", "https://target.example.test/"},
	} {
		if _, err = ParseConfig(args); err == nil {
			t.Errorf("ParseConfig(%q) succeeded, want an incompatibility error", args)
		}
	}
}

func TestParseProxyInsecure(t *testing.T) {
	cfg, err := ParseConfig(
		[]string{"--proxy=https://proxy.example.test", "--proxy-insecure", "https://target.example.test/"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProxyInsecure {
		t.Fatal("ProxyInsecure = false, want true")
	}
	if cfg.Insecure {
		t.Fatal("ProxyInsecure must not enable Insecure for the target")
	}
	cfg, err = ParseConfig([]string{"--insecure", "https://target.example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Insecure || cfg.ProxyInsecure {
		t.Fatalf("--insecure changed wrong TLS flags: Insecure=%t ProxyInsecure=%t", cfg.Insecure, cfg.ProxyInsecure)
	}
	for _, args := range [][]string{
		{"--proxy-insecure", "https://target.example.test/"},
		{"--proxy=http://proxy.example.test", "--proxy-insecure", "https://target.example.test/"},
	} {
		if _, err = ParseConfig(args); err == nil || !strings.Contains(err.Error(), "requires an https:// --proxy") {
			t.Errorf("ParseConfig(%q) error = %v, want HTTPS-proxy requirement", args, err)
		}
	}
}

func TestParseHTTP3ProxyCompatibility(t *testing.T) {
	for _, proxyURL := range []string{"http://proxy.example.test", "https://proxy.example.test"} {
		t.Run(proxyURL, func(t *testing.T) {
			args := []string{"--http3", "--proxy=" + proxyURL, "https://target.example.test/"}
			if _, err := ParseConfig(
				args,
			); err == nil ||
				!strings.Contains(err.Error(), "does not support HTTP(S) proxies") {
				t.Fatalf("ParseConfig(%q) error = %v, want HTTP/3 and HTTP(S)-proxy incompatibility", args, err)
			}
		})
	}
	for _, proxyURL := range []string{"socks5://proxy.example.test", "socks5h://proxy.example.test"} {
		t.Run(proxyURL, func(t *testing.T) {
			args := []string{"--http3", "--proxy=" + proxyURL, "https://target.example.test/"}
			if _, err := ParseConfig(args); err != nil {
				t.Fatalf("ParseConfig(%q) error = %v; SOCKS5 UDP route should remain available", args, err)
			}
		})
	}
}

func TestParseHTTP2PseudoOrder(t *testing.T) {
	cfg, err := ParseConfig(
		[]string{"--http2", "--h2-pseudo-order=authority,method,path,scheme", "https://example.test/"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.HTTP2PseudoOrder, ","); got != ":authority,:method,:path,:scheme" {
		t.Fatalf("pseudo order = %q", got)
	}
	for _, args := range [][]string{
		{"--h2-pseudo-order=method,scheme,authority,path"},
		{"--http2", "--h2-pseudo-order=method,method,authority,path"},
		{"--http2", "--h2-pseudo-order=method,scheme,authority,invalid"},
		{"--http2", "--h2-pseudo-order=method,scheme,path"},
		{"--http2", "--request=CONNECT", "--h2-pseudo-order=method,scheme,authority,path"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-pseudo-order") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2SettingsOrder(t *testing.T) {
	cfg, err := ParseConfig(
		[]string{"--http2", "--h2-settings-order=MAX_FRAME_SIZE,ENABLE_PUSH", "https://example.test/"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.HTTP2SettingsOrder; len(got) != 2 || got[0] != 5 || got[1] != 2 {
		t.Fatalf("settings order = %v", got)
	}
	for _, args := range [][]string{
		{"--h2-settings-order=ENABLE_PUSH"},
		{"--http2", "--h2-settings-order=ENABLE_PUSH,ENABLE_PUSH"},
		{"--http2", "--h2-settings-order=UNKNOWN"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-settings-order") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2DataFrameSize(t *testing.T) {
	cfg, err := ParseConfig([]string{"--http2", "--h2-data-frame-size=7", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP2DataFrameSize != 7 {
		t.Fatalf("data frame size = %d", cfg.HTTP2DataFrameSize)
	}
	for _, args := range [][]string{
		{"--h2-data-frame-size=7"},
		{"--http2", "--h2-data-frame-size=0"},
		{"--http2", "--h2-data-frame-size=16385"},
		{"--http2", "--h2-data-frame-size=garbage"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-data-frame-size") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2Priority(t *testing.T) {
	cfg, err := ParseConfig([]string{"--http2", "--h2-priority=0:256:true", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.HTTP2Priority; got == nil || got.Dependency != 0 || got.Weight != 256 || !got.Exclusive {
		t.Fatalf("HTTP2Priority = %+v", got)
	}
	for _, args := range [][]string{
		{"--h2-priority=0:16:false"},
		{"--http2", "--h2-priority=1:16:false"},
		{"--http2", "--h2-priority=2147483648:16:false"},
		{"--http2", "--h2-priority=0:0:false"},
		{"--http2", "--h2-priority=0:257:false"},
		{"--http2", "--h2-priority=0:16:maybe"},
		{"--http2", "--request=CONNECT", "--h2-priority=0:16:false"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-priority") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2HeaderOrder(t *testing.T) {
	cfg, err := ParseConfig([]string{"--http2", "--h2-header-order=X-B, x-a", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.HTTP2HeaderOrder, ","); got != "x-b,x-a" {
		t.Fatalf("header order = %q", got)
	}
	for _, args := range [][]string{
		{"--h2-header-order=x-a"},
		{"--http2", "--h2-header-order=x-a,X-A"},
		{"--http2", "--h2-header-order=:path"},
		{"--http2", "--h2-header-order=x-a,invalid name"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-header-order") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2HeaderFrameSize(t *testing.T) {
	cfg, err := ParseConfig([]string{"--http2", "--h2-header-frame-size=1024", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP2HeaderFrameSize != 1024 {
		t.Fatalf("HTTP2HeaderFrameSize = %d", cfg.HTTP2HeaderFrameSize)
	}
	for _, args := range [][]string{
		{"--h2-header-frame-size=1024"},
		{"--http2", "--h2-header-frame-size=0"},
		{"--http2", "--h2-header-frame-size=16385"},
		{"--http2", "--request=CONNECT", "--h2-header-frame-size=1024"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil || !strings.Contains(err.Error(), "--h2-header-frame-size") {
			t.Errorf("ParseConfig(%q) = %v", args, err)
		}
	}
}

func TestParseHTTP2FramePadding(t *testing.T) {
	cfg, err := ParseConfig([]string{"--http2", "--h2-frame-padding=16", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP2FramePadding != 16 {
		t.Fatalf("HTTP2FramePadding = %d, want 16", cfg.HTTP2FramePadding)
	}
	for _, args := range [][]string{
		{"--h2-frame-padding=16"},
		{"--http2", "--h2-frame-padding=0"},
		{"--http2", "--h2-frame-padding=256"},
		{"--http2", "--h2-header-frame-size=17", "--h2-frame-padding=16"},
		{"--http2", "--request=CONNECT", "--h2-frame-padding=16"},
	} {
		args = append(args, "https://example.test/")
		if _, err := ParseConfig(args); err == nil {
			t.Errorf("ParseConfig(%q) unexpectedly succeeded", args)
		}
	}
}
