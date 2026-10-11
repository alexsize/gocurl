package gocurl

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDoTargetAndProxyCertificatePoliciesAreIndependent(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, tc := range []struct {
			name                          string
			targetInsecure, proxyInsecure bool
			wantConnects, wantRequests    int32
		}{
			{name: "verify-both"},
			{name: "skip-target-only", targetInsecure: true},
			{name: "skip-proxy-only", proxyInsecure: true, wantConnects: 1},
			{name: "skip-both", targetInsecure: true, proxyInsecure: true, wantConnects: 1, wantRequests: 1},
		} {
			t.Run(fmtPolicyName(imported, tc.name), func(t *testing.T) {
				var connects, requests atomic.Int32
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}))
				target.Config.ErrorLog = log.New(io.Discard, "", 0)
				target.StartTLS()
				defer target.Close()
				proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					connects.Add(1)
					testHTTPConnectHandler(target.Listener.Addr().String()).ServeHTTP(w, r)
				}))
				proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
				proxy.StartTLS()
				defer proxy.Close()
				request := Request{
					URL: target.URL, ProxyURL: proxy.URL, HTTPVersion: "1.1",
					Insecure: tc.targetInsecure, ProxyInsecure: tc.proxyInsecure,
				}
				if imported {
					request.TLSProfile = &TLSProfile{
						ProfilePath:      "../../internal/client/utlsengine/testdata/profile-v1-valid.json",
						ProxyProfilePath: "../../internal/client/utlsengine/testdata/profile-v1-valid.json",
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := NewClient().Do(ctx, request)
				if result != nil {
					_ = result.Close()
				}
				if tc.wantRequests == 1 {
					if err != nil || result == nil || result.Response.StatusCode != http.StatusNoContent {
						t.Fatalf("skip both policies: result=%v error=%v", result, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "certificate") {
					t.Fatalf("verification error = %v, want certificate failure", err)
				}
				if got := connects.Load(); got != tc.wantConnects {
					t.Errorf("CONNECT count = %d, want %d", got, tc.wantConnects)
				}
				if got := requests.Load(); got != tc.wantRequests {
					t.Errorf("target HTTP count = %d, want %d", got, tc.wantRequests)
				}
			})
		}
	}
}

func fmtPolicyName(imported bool, name string) string {
	if imported {
		return "imported-utls/" + name
	}
	return "default-tls/" + name
}

func TestClientDoNonStrictProfileChecksAreIndependent(t *testing.T) {
	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "mismatch.json")
	if err = os.WriteFile(profilePath, []byte(strings.Replace(string(profile), `"value": 771`, `"value": 770`, 1)),
		0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                    string
		targetCheck, proxyCheck bool
	}{
		{name: "disabled"},
		{name: "target", targetCheck: true},
		{name: "proxy", proxyCheck: true},
		{name: "both", targetCheck: true, proxyCheck: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			proxy := httptest.NewTLSServer(testHTTPConnectHandler(target.Listener.Addr().String()))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, doErr := NewClient().Do(ctx, Request{
				URL: target.URL, ProxyURL: proxy.URL,
				HTTPVersion: "1.1", Insecure: true, ProxyInsecure: true, TLSProfile: &TLSProfile{
					ProfilePath: profilePath, Check: tc.targetCheck,
					ProxyProfilePath: profilePath, ProxyCheck: tc.proxyCheck,
				},
			})
			if doErr != nil {
				t.Fatalf("non-strict mismatch blocked HTTP: %v", doErr)
			}
			defer result.Close()
			if result.Response.StatusCode != http.StatusNoContent || len(result.TLSReports) != 2 {
				t.Fatalf("response status=%d reports=%+v", result.Response.StatusCode, result.TLSReports)
			}
			seen := make(map[string]bool)
			for _, report := range result.TLSReports {
				checked := tc.targetCheck
				if report.Leg == "proxy" {
					checked = tc.proxyCheck
				} else if report.Leg != "target" {
					t.Fatalf("unexpected TLS leg %q", report.Leg)
				}
				seen[report.Leg] = true
				want := "OBSERVED"
				if checked {
					want = "MISMATCH"
				}
				if report.CaptureStatus != want || report.Actual == nil ||
					(checked && len(report.Diff) == 0) || (!checked && len(report.Diff) != 0) {
					t.Errorf("%s report = %+v, want %s with appropriate diff", report.Leg, report, want)
				}
			}
			if !seen["target"] || !seen["proxy"] {
				t.Errorf("missing independent TLS leg: %v", seen)
			}
		})
	}
}
