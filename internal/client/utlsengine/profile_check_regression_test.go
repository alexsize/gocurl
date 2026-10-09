package utlsengine

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProfileCheckPreservesStatusAndDiffPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*ClientProfile, *Fingerprint)
		status   string
		paths    []string
		policies []string
	}{
		{
			name: "MUST mismatch wins over unsupported and SHOULD",
			mutate: func(p *ClientProfile, _ *Fingerprint) {
				p.Expected.JA3 = "different"
				p.Expected.NormalizationVersion = "unknown"
				p.Policy.Constraints = []ClientProfileConstraint{{Path: "/missing", Operator: "present"}}
				p.Policy.MustMatch = []string{"fields.alpn"}
				p.Fields.ALPN = []string{"http/1.1"}
				p.Policy.ShouldMatch = []string{"unknown"}
			},
			status:   "MISMATCH",
			paths:    []string{"expected.ja3", "expected.normalization_version", "/missing", "fields.alpn", "unknown"},
			policies: []string{"MUST", "UNSUPPORTED: normalization version is not supported", "CONSTRAINT", "MUST", "UNSUPPORTED"},
		},
		{
			name: "unsupported wins over SHOULD",
			mutate: func(p *ClientProfile, _ *Fingerprint) {
				p.Expected.NormalizationVersion = "unknown"
				p.Policy.ShouldMatch = []string{"unknown"}
			},
			status:   "UNSUPPORTED",
			paths:    []string{"expected.normalization_version", "unknown"},
			policies: []string{"UNSUPPORTED: normalization version is not supported", "UNSUPPORTED"},
		},
		{
			name: "SHOULD mismatch is partial",
			mutate: func(p *ClientProfile, _ *Fingerprint) {
				p.Policy.ShouldMatch = []string{"fields.alpn"}
				p.Fields.ALPN = []string{"http/1.1"}
			},
			status: "PARTIAL_MATCH", paths: []string{"fields.alpn"}, policies: []string{"SHOULD"},
		},
		{
			name:   "normalized hash mismatch is MUST",
			mutate: func(p *ClientProfile, _ *Fingerprint) { p.Expected.NormalizedSHA256 = "different" },
			status: "MISMATCH", paths: []string{"expected.normalized_sha256"}, policies: []string{"MUST"},
		},
		{
			name: "invalid normalized document is unsupported",
			mutate: func(p *ClientProfile, actual *Fingerprint) {
				actual.normalizedDocument = []byte("{")
				p.Policy.Constraints = []ClientProfileConstraint{{Path: "/legacy_version", Operator: "equals", Value: json.RawMessage("771")}}
			},
			status: "UNSUPPORTED", paths: []string{"/legacy_version"},
			policies: []string{"UNSUPPORTED: invalid normalized ClientHello document"},
		},
		{
			name: "normalization error precedes malformed document",
			mutate: func(p *ClientProfile, actual *Fingerprint) {
				actual.NormalizationError = "broken extension"
				actual.normalizedDocument = []byte("{")
				p.Policy.Constraints = []ClientProfileConstraint{{Path: "/legacy_version", Operator: "present"}}
			},
			status: "UNSUPPORTED", paths: []string{"expected.normalized_sha256", "/legacy_version"},
			policies: []string{"UNSUPPORTED: broken extension", "UNSUPPORTED: normalized ClientHello document is unavailable"},
		},
		{
			name: "matching constraint keeps MATCH",
			mutate: func(p *ClientProfile, _ *Fingerprint) {
				p.Policy.Constraints = []ClientProfileConstraint{{Path: "/legacy_version", Operator: "equals", Value: json.RawMessage("771")}}
			},
			status: "MATCH",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ClientProfile{Expected: ClientProfileExpected{
				JA3:                  "ja3",
				JA3Hash:              "hash",
				JA4:                  "ja4",
				NormalizedSHA256:     "normalized",
				NormalizationVersion: TLSNormalizationVersion,
			}}
			actual := Fingerprint{
				JA3String: "ja3", JA3: "hash", JA4: "ja4", ALPN: []string{"h2"},
				NormalizedSHA256: "normalized", NormalizationVersion: TLSNormalizationVersion,
				normalizedDocument: []byte(`{"legacy_version":771}`),
			}
			tc.mutate(&p, &actual)
			result := CheckClientProfile(p, actual)
			if result.Status != tc.status {
				t.Fatalf("status = %s, want %s: %+v", result.Status, tc.status, result.Diffs)
			}
			var paths, policies []string
			for _, diff := range result.Diffs {
				paths = append(paths, diff.Path)
				policies = append(policies, diff.Policy)
			}
			if !reflect.DeepEqual(paths, tc.paths) || !reflect.DeepEqual(policies, tc.policies) {
				t.Fatalf("diffs = %v, %v; want %v, %v", paths, policies, tc.paths, tc.policies)
			}
		})
	}
}
