package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profileFixturePath(name string) string {
	return filepath.Join("..", "client", "utlsengine", "testdata", name)
}

func TestParseConfigImportsTLSProfile(t *testing.T) {
	cfg, err := ParseConfig(
		[]string{"--tls-profile", profileFixturePath("profile-v1-valid.json"), "https://example.test"},
	)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.TLSProfile == nil || cfg.TLSProfile.Preset != "Chrome-120" || len(cfg.TLSProfile.ALPN) != 1 {
		t.Fatalf("TLSProfile = %+v, want imported Chrome-120 profile", cfg.TLSProfile)
	}
	if !containsALPN(cfg.TLSProfileUnsupported, "fields.cipher_suites") {
		t.Fatalf("unsupported profile fields = %v, want cipher suites reported", cfg.TLSProfileUnsupported)
	}
}

func TestParseConfigRejectsUnsupportedTLSProfileBeforeTransport(t *testing.T) {
	_, err := ParseConfig(
		[]string{"--tls-profile", profileFixturePath("profile-v1-unsupported.json"), "https://example.test"},
	)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") {
		t.Fatalf("ParseConfig() error = %v, want unsupported profile error", err)
	}
}

func TestParseConfigEnablesTLSProfileCheck(t *testing.T) {
	args := []string{
		"--tls-profile-check",
		"--tls-profile",
		profileFixturePath("profile-v1-valid.json"),
		"https://example.test",
	}
	cfg, err := ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !cfg.TLSProfileCheck || cfg.TLSProfileStrict || cfg.TLSProfileDocument == nil {
		t.Fatalf("profile-check config = %+v, want check enabled with imported document", cfg)
	}

	args[0] = "--tls-profile-strict"
	cfg, err = ParseConfig(args)
	if err != nil {
		t.Fatalf("ParseConfig(strict) error = %v", err)
	}
	if !cfg.TLSProfileCheck || !cfg.TLSProfileStrict {
		t.Fatalf(
			"strict profile-check config = check:%t strict:%t, want both enabled",
			cfg.TLSProfileCheck,
			cfg.TLSProfileStrict,
		)
	}
}

func TestParseConfigRequiresProfileForTLSProfileCheck(t *testing.T) {
	for _, flag := range []string{"--tls-profile-check", "--tls-profile-strict"} {
		t.Run(flag, func(t *testing.T) {
			if _, err := ParseConfig(
				[]string{flag, "https://example.test"},
			); err == nil ||
				!strings.Contains(err.Error(), "require --tls-profile") {
				t.Fatalf("ParseConfig() error = %v, want profile requirement", err)
			}
		})
	}
}

func TestParseConfigRejectsIncompatibleTLSProfileOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "non-https",
			args: []string{"--tls-profile", profileFixturePath("profile-v1-valid.json"), "http://example.test"},
		},
		{
			name: "ech",
			args: []string{
				"--ech",
				"--tls-profile",
				profileFixturePath("profile-v1-valid.json"),
				"https://example.test",
			},
		},
		{
			name: "forced h2 conflict",
			args: []string{
				"--http2",
				"--tls-profile",
				profileFixturePath("profile-v1-valid.json"),
				"https://example.test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig(tt.args); err == nil {
				t.Fatal("ParseConfig() unexpectedly accepted incompatible TLS profile options")
			}
		})
	}
}

func TestParseConfigImportsIndependentProxyTLSProfile(t *testing.T) {
	profilePath := profileFixturePath("profile-v1-valid.json")
	cfg, err := ParseConfig([]string{
		"--proxy", "https://proxy.example",
		"--proxy-tls-profile-strict", "--proxy-tls-profile", profilePath,
		"--tls-profile-check", "--tls-profile", profilePath,
		"https://target.example",
	})
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ProxyTLSProfile == nil || cfg.ProxyTLSProfileDocument == nil ||
		!cfg.ProxyTLSProfileCheck || !cfg.ProxyTLSProfileStrict {
		t.Fatalf("proxy TLS profile config = %+v, want strict independent proxy profile", cfg)
	}
	if cfg.TLSProfile == nil || cfg.TLSProfileDocument == nil || !cfg.TLSProfileCheck {
		t.Fatalf("target TLS profile config = %+v, want independent target check", cfg)
	}
}

func TestParseConfigRejectsProxyTLSProfileWithoutHTTPSProxy(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no proxy",
			args: []string{
				"--proxy-tls-profile",
				profileFixturePath("profile-v1-valid.json"),
				"https://target.example",
			},
		},
		{
			name: "plain HTTP proxy",
			args: []string{
				"--proxy",
				"http://proxy.example",
				"--proxy-tls-profile",
				profileFixturePath("profile-v1-valid.json"),
				"https://target.example",
			},
		},
		{
			name: "SOCKS proxy",
			args: []string{
				"--proxy",
				"socks5://proxy.example",
				"--proxy-tls-profile",
				profileFixturePath("profile-v1-valid.json"),
				"https://target.example",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseConfig(
				test.args,
			); err == nil ||
				!strings.Contains(err.Error(), "requires an https:// --proxy") {
				t.Fatalf("ParseConfig() error = %v, want HTTPS-proxy requirement", err)
			}
		})
	}
}

func TestParseConfigRequiresProxyTLSProfileForProxyCheck(t *testing.T) {
	for _, flag := range []string{"--proxy-tls-profile-check", "--proxy-tls-profile-strict"} {
		t.Run(flag, func(t *testing.T) {
			if _, err := ParseConfig(
				[]string{flag, "--proxy", "https://proxy.example", "https://target.example"},
			); err == nil ||
				!strings.Contains(err.Error(), "require --proxy-tls-profile") {
				t.Fatalf("ParseConfig() error = %v, want proxy-profile requirement", err)
			}
		})
	}
}

func TestParseConfigRejectsProxyTLSProfileWithoutHTTP11ALPN(t *testing.T) {
	profilePath := profileFixturePath("profile-v1-valid.json")
	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), `"http/1.1"`, `"h2"`))
	path := filepath.Join(t.TempDir(), "proxy-h2-profile.json")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ParseConfig([]string{
		"--proxy", "https://proxy.example", "--proxy-tls-profile", path, "https://target.example",
	})
	if err == nil || !strings.Contains(err.Error(), "must offer only http/1.1") {
		t.Fatalf("ParseConfig() error = %v, want proxy HTTP/1.1 ALPN requirement", err)
	}
}
