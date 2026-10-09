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

func TestDecodeClientProfileGolden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := DecodeClientProfile(data)
	if err != nil {
		t.Fatalf("DecodeClientProfile() error = %v", err)
	}
	if profile.SchemaVersion != ProfileSchemaVersion || profile.Fields.ALPN[0] != "http/1.1" {
		t.Fatalf("unexpected decoded profile: %+v", profile)
	}
}

func TestDecodeClientProfileRejectsUnsupportedMUSTGolden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "profile-v1-unsupported.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeClientProfile(data); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") {
		t.Fatalf("DecodeClientProfile() error = %v, want unsupported MUST field", err)
	}
}

func TestClientProfileMaterializesTLSFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := DecodeClientProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	profile.Replayability.Unsupported = nil
	materialized, unsupported, err := profile.Materialize()
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	if materialized.Preset != "Chrome-120" || len(materialized.ExtensionOrder) != 0 || len(materialized.ALPN) != 1 {
		t.Fatalf("unexpected uTLS profile: %+v", materialized)
	}
	if !reflect.DeepEqual(materialized.CipherSuites, profile.Fields.CipherSuites) ||
		!reflect.DeepEqual(materialized.SupportedVersions, profile.Fields.SupportedVersions) ||
		!reflect.DeepEqual(materialized.SupportedGroups, profile.Fields.SupportedGroups) ||
		!reflect.DeepEqual(materialized.SignatureAlgorithms, profile.Fields.SignatureAlgorithms) {
		t.Fatalf("materialized TLS fields = %+v, source fields = %+v", materialized, profile.Fields)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unsupported fields = %v, want none", unsupported)
	}
	profile.Policy.MustMatch = []string{
		"fields.cipher_suites", "fields.supported_versions", "fields.supported_groups", "fields.signature_algorithms",
	}
	if _, unsupported, err = profile.Materialize(); err != nil || len(unsupported) != 0 {
		t.Fatalf("Materialize(MUST TLS fields) = unsupported %v, error %v", unsupported, err)
	}

	profile.Replayability.Unsupported = []string{"fields.cipher_suites"}
	profile.Policy.MustMatch = nil
	materialized, unsupported, err = profile.Materialize()
	if err != nil {
		t.Fatalf("Materialize(non-replayable optional field) error = %v", err)
	}
	if !reflect.DeepEqual(unsupported, []string{"fields.cipher_suites"}) || len(materialized.CipherSuites) != 0 {
		t.Fatalf("non-replayable cipher suites = %+v, unsupported = %v", materialized.CipherSuites, unsupported)
	}
}

func TestClientProfileMaterializeRejectsUnsupportedReplayability(t *testing.T) {
	profile := ClientProfile{
		SchemaVersion: ProfileSchemaVersion,
		ID:            "observed",
		Version:       1,
		Name:          "Observed unsupported profile",
		ProfileType:   "OBSERVED",
		Engine:        ClientProfileEngine{Name: "JA3Proxy", Version: "1"},
		Replayability: ClientProfileReplayability{Status: "UNSUPPORTED"},
	}
	if _, _, err := profile.Materialize(); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") {
		t.Fatalf("Materialize() error = %v, want UNSUPPORTED status error", err)
	} else {
		var unsupportedErr *UnsupportedProfileError
		if !errors.As(err, &unsupportedErr) || unsupportedErr.Status() != "UNSUPPORTED" {
			t.Fatalf("Materialize() error type = %T, want UnsupportedProfileError", err)
		}
	}
}

func TestDecodeClientProfileRejectsInvalidDocuments(t *testing.T) {
	valid, err := os.ReadFile(filepath.Join("testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "unknown major",
			data: strings.Replace(string(valid), ProfileSchemaVersion, "ja3proxy-client-profile/2", 1),
			want: "unsupported",
		},
		{
			name: "unknown field",
			data: strings.Replace(string(valid), `"name":`, `"unexpected": true, "name":`, 1),
			want: "unknown field",
		},
		{
			name: "unsupported constraint operator",
			data: strings.Replace(string(valid), `"operator": "equals"`, `"operator": "EQUALS_TARGET_HOST"`, 1),
			want: "UNSUPPORTED",
		},
		{
			name: "invalid constraint JSON pointer",
			data: strings.Replace(string(valid), `"/legacy_version"`, `"/legacy~2version"`, 1),
			want: "JSON Pointer",
		},
		{name: "trailing value", data: string(valid) + ` {}`, want: "invalid character"},
		{
			name: "empty identity",
			data: strings.Replace(string(valid), `"id": "chrome-120-example"`, `"id": " "`, 1),
			want: "requires non-empty",
		},
		{
			name: "missing required object",
			data: strings.Replace(string(valid), `  "expected": {`, `  "unexpected": {`, 1),
			want: `required field "expected"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, decodeErr := DecodeClientProfile(
				[]byte(tt.data),
			); decodeErr == nil ||
				!strings.Contains(decodeErr.Error(), tt.want) {
				t.Fatalf("DecodeClientProfile() error = %v, want containing %q", decodeErr, tt.want)
			}
		})
	}
}

func TestClientProfileCustomALPNPolicyRequiresCustomProtocols(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := DecodeClientProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	profile.Fields.CustomALPN = nil
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "custom_alpn is required") {
		t.Fatalf("Validate() error = %v, want CUSTOM policy to require custom_alpn", err)
	}
}

func TestClientProfileSchemaRequiresCustomALPNForCustomPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "ja3proxy-client-profile-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		AllOf []struct {
			If struct {
				Properties struct {
					Fields struct {
						Properties map[string]map[string]string `json:"properties"`
					} `json:"fields"`
				} `json:"properties"`
			} `json:"if"`
			Then struct {
				Properties struct {
					Fields struct {
						Properties map[string]map[string]string `json:"properties"`
						Required   []string                     `json:"required"`
					} `json:"fields"`
				} `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
	}
	if err = json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode profile schema: %v", err)
	}
	if len(schema.AllOf) != 1 || schema.AllOf[0].If.Properties.Fields.Properties["alpn_policy"]["const"] != "CUSTOM" {
		t.Fatalf("schema has no CUSTOM ALPN conditional: %+v", schema.AllOf)
	}
	then := schema.AllOf[0].Then.Properties.Fields
	if !reflect.DeepEqual(then.Required, []string{"custom_alpn"}) ||
		then.Properties["custom_alpn"]["$ref"] != "#/$defs/nonEmptyStringList" {
		t.Fatalf("CUSTOM ALPN schema requirement = %+v, want required non-empty custom_alpn", then)
	}
}

func TestClientProfileRejectsInvalidSupportedVersions(t *testing.T) {
	profile := ClientProfile{
		SchemaVersion: ProfileSchemaVersion,
		ID:            "bad-version",
		Version:       1,
		Name:          "Invalid TLS versions",
		ProfileType:   "CUSTOM",
		Fields:        ClientProfileFields{SupportedVersions: []uint16{0x0304, 0x0305}},
		Engine:        ClientProfileEngine{Name: "uTLS", Version: "test"},
		BasePreset:    &ClientProfilePreset{Client: "Chrome", Version: "120"},
		Replayability: ClientProfileReplayability{Status: "REPLAYABLE"},
	}
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported TLS version") {
		t.Fatalf("Validate() error = %v, want unsupported TLS version", err)
	}
	profile.Fields.SupportedVersions = []uint16{0x0304, 0x0304}
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate TLS version") {
		t.Fatalf("Validate(duplicate) error = %v, want duplicate TLS version", err)
	}
}

func TestClientProfileValidatesConstraintOperatorsAndPaths(t *testing.T) {
	profile := ClientProfile{Policy: ClientProfilePolicy{Constraints: []ClientProfileConstraint{{
		Path: "/legacy_version", Operator: "equals", Value: json.RawMessage("771"),
	}}}}
	if err := validateProfileConstraint(profile.Policy.Constraints[0]); err != nil {
		t.Fatalf("valid constraint rejected: %v", err)
	}
	tests := []struct {
		name       string
		constraint ClientProfileConstraint
		want       string
	}{
		{
			name:       "unknown operator",
			constraint: ClientProfileConstraint{Path: "/x", Operator: "EQUALS_TARGET_HOST"},
			want:       "UNSUPPORTED",
		},
		{
			name:       "malformed pointer escape",
			constraint: ClientProfileConstraint{Path: "/x~2y", Operator: "present"},
			want:       "JSON Pointer",
		},
		{
			name:       "equals missing value",
			constraint: ClientProfileConstraint{Path: "/x", Operator: "equals"},
			want:       "requires one JSON value",
		},
		{
			name:       "present rejects value",
			constraint: ClientProfileConstraint{Path: "/x", Operator: "present", Value: json.RawMessage(`true`)},
			want:       "does not accept",
		},
		{
			name:       "one_of requires values",
			constraint: ClientProfileConstraint{Path: "/x", Operator: "one_of"},
			want:       "requires values",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateProfileConstraint(tt.constraint); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateProfileConstraint() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckClientProfileEvaluatesConstraintsAgainstTLSNorm(t *testing.T) {
	hello := buildClientHelloForTest(0x0303, []uint16{0x0a0a, 0x1301}, []testExtension{
		{id: 0, data: sniExtensionForTest("private.example")},
	})
	actual, err := FingerprintClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	profile := ClientProfile{Policy: ClientProfilePolicy{
		IgnoredDynamic: []string{"client_random", "session_id_bytes"},
		Constraints: []ClientProfileConstraint{
			{Path: "/extensions/0/fields/present", Operator: "present"},
			{Path: "/legacy_version", Operator: "equals", Value: json.RawMessage("771")},
			{
				Path:     "/ciphers/0",
				Operator: "one_of",
				Values:   []json.RawMessage{json.RawMessage(`4865`), json.RawMessage(`"GREASE"`)},
			},
		},
	}}
	got := CheckClientProfile(profile, actual)
	if got.Status != "MATCH" || len(got.Diffs) != 0 {
		t.Fatalf("matching constraints = %+v, want MATCH", got)
	}
	if !reflect.DeepEqual(got.IgnoredDynamic, profile.Policy.IgnoredDynamic) {
		t.Fatalf("ignored_dynamic report = %v, want %v", got.IgnoredDynamic, profile.Policy.IgnoredDynamic)
	}

	profile.Policy.Constraints[1].Value = json.RawMessage("772")
	got = CheckClientProfile(profile, actual)
	if got.Status != "MISMATCH" || len(got.Diffs) != 1 || got.Diffs[0].Policy != "CONSTRAINT" ||
		got.Diffs[0].Path != "/legacy_version" {
		t.Fatalf("violated constraint = %+v, want one constraint MISMATCH", got)
	}

	profile.Policy.Constraints = []ClientProfileConstraint{{Path: "/not-present", Operator: "present"}}
	got = CheckClientProfile(profile, actual)
	if got.Status != "MISMATCH" || len(got.Diffs) != 1 {
		t.Fatalf("missing constrained path = %+v, want MISMATCH", got)
	}

	got = CheckClientProfile(profile, Fingerprint{})
	if got.Status != "UNSUPPORTED" || len(got.Diffs) != 1 || !strings.HasPrefix(got.Diffs[0].Policy, "UNSUPPORTED:") {
		t.Fatalf("constraints without normalized document = %+v, want UNSUPPORTED", got)
	}
}

func TestConnectionReportRetainsProfilePolicy(t *testing.T) {
	profile := ClientProfile{
		Engine: ClientProfileEngine{Name: "uTLS", Version: "test"},
		Policy: ClientProfilePolicy{
			Constraints:    []ClientProfileConstraint{{Path: "/legacy_version", Operator: "present"}},
			IgnoredDynamic: []string{"client_random"},
		},
	}
	check := ProfileCheckResult{Status: "MATCH"}
	report := NewConnectionReport(profile, check, "conn-1", 1, 1)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if _, ok := actual["constraints"]; !ok {
		t.Fatalf("connection JSON omits profile constraints: %s", encoded)
	}
	if values, ok := actual["ignored_dynamic"].([]any); !ok || len(values) != 1 || values[0] != "client_random" {
		t.Fatalf("connection ignored_dynamic = %#v, want client_random", actual["ignored_dynamic"])
	}
}

func TestCheckClientProfileStatuses(t *testing.T) {
	profile := ClientProfile{
		Expected: ClientProfileExpected{JA3: "raw", JA3Hash: "hash", JA4: "ja4"},
		Fields:   ClientProfileFields{ALPN: []string{"h2"}, CipherSuites: []uint16{0x1301}},
		Policy: ClientProfilePolicy{
			MustMatch:   []string{"fields.alpn"},
			ShouldMatch: []string{"fields.cipher_suites"},
		},
	}
	actual := Fingerprint{
		JA3String:    "raw",
		JA3:          "hash",
		JA4:          "ja4",
		ALPN:         []string{"h2"},
		CipherSuites: []uint16{0x1301},
	}
	if got := CheckClientProfile(profile, actual); got.Status != "MATCH" || len(got.Diffs) != 0 {
		t.Fatalf("exact check = %+v, want MATCH without differences", got)
	}

	actual.ALPN = []string{"http/1.1"}
	if got := CheckClientProfile(profile, actual); got.Status != "MISMATCH" || len(got.Diffs) != 1 {
		t.Fatalf("MUST mismatch = %+v, want MISMATCH", got)
	}

	profile.Policy.MustMatch = nil
	profile.Expected = ClientProfileExpected{}
	actual.CipherSuites = []uint16{0x1302}
	if got := CheckClientProfile(profile, actual); got.Status != "PARTIAL_MATCH" {
		t.Fatalf("SHOULD mismatch = %+v, want PARTIAL_MATCH", got)
	}

	profile.Policy.ShouldMatch = nil
	profile.Expected.NormalizedSHA256 = "expected-tls-norm-hash"
	profile.Expected.NormalizationVersion = TLSNormalizationVersion
	actual.NormalizedSHA256 = "actual-tls-norm-hash"
	if got := CheckClientProfile(profile, actual); got.Status != "MISMATCH" {
		t.Fatalf("normalized fingerprint mismatch = %+v, want MISMATCH", got)
	}
	profile.Expected.NormalizationVersion = "TLS-NORM-unknown"
	if got := CheckClientProfile(profile, actual); got.Status != "UNSUPPORTED" {
		t.Fatalf("unknown normalization version = %+v, want UNSUPPORTED", got)
	}
	profile.Expected.NormalizationVersion = TLSNormalizationVersion
	actual.NormalizationError = "malformed extension payload"
	if got := CheckClientProfile(profile, actual); got.Status != "UNSUPPORTED" {
		t.Fatalf("unavailable normalized fingerprint = %+v, want UNSUPPORTED", got)
	}
}

func TestCheckClientProfileComparesSupportedTLSFields(t *testing.T) {
	profile := ClientProfile{
		Fields: ClientProfileFields{
			CipherSuites:        []uint16{0x1301, 0x1302},
			SupportedVersions:   []uint16{0x0304, 0x0303},
			SupportedGroups:     []uint16{0x001d, 0x0017},
			SignatureAlgorithms: []uint16{0x0403, 0x0804},
		},
		Policy: ClientProfilePolicy{MustMatch: []string{
			"fields.cipher_suites",
			"fields.supported_versions",
			"fields.supported_groups",
			"fields.signature_algorithms",
		}},
	}
	actual := Fingerprint{
		CipherSuites:        []uint16{0x1301, 0x1302},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		SupportedGroups:     []uint16{0x001d, 0x0017},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}
	if got := CheckClientProfile(profile, actual); got.Status != "MATCH" {
		t.Fatalf("exact TLS field check = %+v, want MATCH", got)
	}
	actual.SupportedGroups = []uint16{0x0017, 0x001d}
	if got := CheckClientProfile(
		profile,
		actual,
	); got.Status != "MISMATCH" || len(got.Diffs) != 1 ||
		got.Diffs[0].Path != "fields.supported_groups" {
		t.Fatalf("supported-groups mismatch = %+v, want one MUST mismatch", got)
	}
}

func TestCaptureProfileCheckReportsIncompleteCapture(t *testing.T) {
	result, err := CaptureProfileCheck(ClientProfile{}, nil)
	if err == nil || result.Status != "INCOMPLETE" {
		t.Fatalf("CaptureProfileCheck(nil) = %+v, %v; want INCOMPLETE with error", result, err)
	}
}

func TestCaptureObservationsDistinguishesNotObservedAndIncomplete(t *testing.T) {
	if got := CaptureObservations(nil); len(got) != 1 || got[0].Status != "NOT_OBSERVED" {
		t.Fatalf("CaptureObservations(nil) = %+v, want NOT_OBSERVED", got)
	}
	capture := &CaptureConn{Conn: &writeOnlyConn{}}
	if _, err := capture.Write([]byte{22, 3, 1, 0, 10, 1, 0}); err != nil {
		t.Fatal(err)
	}
	capture.StopCapture()
	got := CaptureObservations(capture)
	if len(got) != 1 || got[0].Status != "INCOMPLETE" || got[0].Error == "" {
		t.Fatalf("partial wire capture = %+v, want INCOMPLETE with a diagnostic", got)
	}
}

func TestProfileCheckErrorExitCodes(t *testing.T) {
	tests := []struct {
		status string
		code   int
	}{
		{status: "UNSUPPORTED", code: 2},
		{status: "CONNECTION_ERROR", code: 3},
		{status: "MISMATCH", code: 4},
		{status: "PARTIAL_MATCH", code: 4},
		{status: "INCOMPLETE", code: 5},
		{status: "NOT_OBSERVED", code: 5},
		{status: "REUSED_CONNECTION", code: 5},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := NewProfileCheckError(tt.status, nil).ExitCode(); got != tt.code {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.code)
			}
		})
	}
}
