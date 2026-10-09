package utlsengine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func profileForRefactorTest(t *testing.T) ClientProfile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeClientProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	p.Replayability.Unsupported = nil
	return p
}

func TestProfileValidationPreservesErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ClientProfile)
		want   string
	}{
		{"schema before identity", func(p *ClientProfile) { p.SchemaVersion = "bad"; p.ID = "" }, "schema_version"},
		{"identity before type", func(p *ClientProfile) { p.ID = ""; p.ProfileType = "bad" }, "requires non-empty id/name"},
		{"type before ALPN", func(p *ClientProfile) { p.ProfileType = "bad"; p.Fields.ALPNPolicy = "bad" }, "profile_type"},
		{"ALPN before ALPS", func(p *ClientProfile) { p.Fields.ALPNPolicy = "bad"; p.Fields.ALPSPolicy = "bad" }, "fields.alpn_policy"},
		{"custom ALPN before ALPS", func(p *ClientProfile) {
			p.Fields.ALPNPolicy = "CUSTOM"
			p.Fields.CustomALPN = nil
			p.Fields.ALPSPolicy = "bad"
		}, "custom_alpn is required"},
		{"ALPS before replayability", func(p *ClientProfile) { p.Fields.ALPSPolicy = "bad"; p.Replayability.Status = "bad" }, "fields.alps_policy"},
		{"replayability before mode", func(p *ClientProfile) { p.Replayability.Status = "bad"; p.ProfileMode = "bad" }, "replayability.status"},
		{"mode before randomized ALPN", func(p *ClientProfile) { p.ProfileMode = "bad"; p.ProfileType = "RANDOMIZED"; p.RandomizedALPN = "bad" }, "profile_mode"},
		{"randomized ALPN before engine", func(p *ClientProfile) { p.ProfileType = "RANDOMIZED"; p.RandomizedALPN = "bad"; p.Engine.Name = "" }, "randomized_alpn"},
		{"engine before unsupported metadata", func(p *ClientProfile) { p.Engine.Name = ""; p.Replayability.Unsupported = []string{""} }, "engine name and version"},
		{"unsupported metadata before versions", func(p *ClientProfile) {
			p.Replayability.Unsupported = []string{""}
			p.Fields.SupportedVersions = []uint16{0}
		}, "unsupported entries"},
		{"versions before constraints", func(p *ClientProfile) {
			p.Fields.SupportedVersions = []uint16{0}
			p.Policy.Constraints = []ClientProfileConstraint{{}}
		}, "unsupported TLS version"},
		{"constraints before source", func(p *ClientProfile) {
			p.Policy.Constraints = []ClientProfileConstraint{{}}
			p.Source = &ClientProfileSource{}
		}, "JSON Pointer path and operator"},
		{"source before MUST", func(p *ClientProfile) { p.Source = &ClientProfileSource{}; p.Policy.MustMatch = []string{"unknown"} }, "source requires"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileForRefactorTest(t)
			tc.mutate(&p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestProfileMaterializePreservesUnsupportedOrderAndCopies(t *testing.T) {
	p := profileForRefactorTest(t)
	zeroPadding := uint16(0)
	p.Fields.ALPN = []string{"h2"}
	p.Fields.CustomALPN = []string{"http/1.1"}
	p.Fields.ALPNPolicy = "DOWNSTREAM"
	p.Fields.ALPSPolicy = "PROFILE"
	p.Fields.ALPS = []string{"h2"}
	p.Fields.CustomALPS = []string{"h2"}
	p.Fields.PaddingLength = &zeroPadding
	p.Replayability.Unsupported = []string{"fields.custom_alps", "exporter.extra", "fields.cipher_suites"}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, unsupported, err := p.Materialize()
	if err != nil {
		t.Fatal(err)
	}
	wantUnsupported := []string{
		"fields.custom_alps", "exporter.extra", "fields.cipher_suites",
		"fields.alps", "fields.alps_policy", "fields.alpn_policy", "fields.padding_length",
	}
	if !reflect.DeepEqual(unsupported, wantUnsupported) {
		t.Fatalf("unsupported = %v, want %v", unsupported, wantUnsupported)
	}
	if len(got.CipherSuites) != 0 || !reflect.DeepEqual(got.ALPN, []string{"http/1.1"}) {
		t.Fatalf("materialized cipher/ALPN fields = %+v", got)
	}
	got.ALPN[0] = "changed"
	got.SupportedVersions[0] = 0
	unsupported[0] = "changed"
	after, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Materialize returned aliases into the source profile")
	}
}

func TestProfileMaterializePreservesMUSTErrors(t *testing.T) {
	for _, path := range []string{"fields.extension_order", "fields.cipher_suites", "fields.supported_groups"} {
		t.Run(path, func(t *testing.T) {
			p := profileForRefactorTest(t)
			p.Policy.MustMatch = []string{path}
			p.Fields.ExtensionOrder = nil
			p.Fields.CipherSuites = nil
			p.Fields.SupportedGroups = nil
			got, _, err := p.Materialize()
			if err == nil || !strings.Contains(err.Error(), "has no value") || !reflect.DeepEqual(got, Profile{}) {
				t.Fatalf("Materialize(%q) = %+v, %v", path, got, err)
			}
			p = profileForRefactorTest(t)
			p.Policy.MustMatch = []string{path}
			if path == "fields.extension_order" {
				p.Fields.ExtensionOrder = []uint16{0}
			}
			p.Replayability.Unsupported = []string{path}
			_, unsupported, err := p.Materialize()
			var unsupportedErr *UnsupportedProfileError
			if !errors.As(err, &unsupportedErr) || unsupportedErr.Field != path ||
				!reflect.DeepEqual(unsupported, []string{path}) {
				t.Fatalf("Materialize unsupported MUST %q = %v, %v", path, unsupported, err)
			}
		})
	}
}
