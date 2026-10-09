package utlsengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ProfileSchemaVersion identifies the supported JA3Proxy profile interchange format.
const ProfileSchemaVersion = "ja3proxy-client-profile/1"

// UnsupportedProfileError reports a profile requirement this uTLS materializer cannot satisfy.
type UnsupportedProfileError struct {
	Field string
}

func (e *UnsupportedProfileError) Error() string {
	return fmt.Sprintf("client profile status UNSUPPORTED: field %q cannot be materialized", e.Field)
}

// Status is the machine-readable profile import status.
func (e *UnsupportedProfileError) Status() string { return "UNSUPPORTED" }

// ClientProfile is the versioned interchange format exported by JA3Proxy.
// It deliberately contains configuration and fingerprints only, never capture bytes or secrets.
type ClientProfile struct {
	SchemaVersion  string                     `json:"schema_version"`
	ID             string                     `json:"id"`
	Version        int                        `json:"version"`
	Name           string                     `json:"name"`
	ProfileType    string                     `json:"profile_type"`
	Fields         ClientProfileFields        `json:"fields"`
	Policy         ClientProfilePolicy        `json:"policy"`
	Expected       ClientProfileExpected      `json:"expected"`
	Engine         ClientProfileEngine        `json:"engine"`
	BasePreset     *ClientProfilePreset       `json:"base_preset,omitempty"`
	HostPatterns   []string                   `json:"host_patterns,omitempty"`
	ProfileMode    string                     `json:"profile_mode,omitempty"`
	RandomizedALPN string                     `json:"randomized_alpn,omitempty"`
	Source         *ClientProfileSource       `json:"source,omitempty"`
	Replayability  ClientProfileReplayability `json:"replayability"`
}

// ClientProfilePreset identifies the base browser preset used for materialization.
type ClientProfilePreset struct {
	Client  string `json:"client"`
	Version string `json:"version"`
}

// ClientProfileSource records the observation and fingerprint metadata of the export.
type ClientProfileSource struct {
	ObservationID        string `json:"observation_id"`
	ServerName           string `json:"server_name,omitempty"`
	JA3                  string `json:"ja3"`
	JA3Hash              string `json:"ja3_hash"`
	JA4                  string `json:"ja4"`
	NormalizedSHA256     string `json:"normalized_sha256"`
	NormalizationVersion string `json:"normalization_version"`
}

// ClientProfileReplayability declares replay limitations and exporter warnings.
type ClientProfileReplayability struct {
	Status      string   `json:"status"`
	Unsupported []string `json:"unsupported,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// ClientProfileFields contains the requested configurable ClientHello fields.
type ClientProfileFields struct {
	CipherSuites        []uint16 `json:"cipher_suites,omitempty"`
	ExtensionOrder      []uint16 `json:"extension_order,omitempty"`
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`
	SupportedGroups     []uint16 `json:"supported_groups,omitempty"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	ALPN                []string `json:"alpn,omitempty"`
	ALPS                []string `json:"alps,omitempty"`
	ALPNPolicy          string   `json:"alpn_policy,omitempty"`
	CustomALPN          []string `json:"custom_alpn,omitempty"`
	ALPSPolicy          string   `json:"alps_policy,omitempty"`
	CustomALPS          []string `json:"custom_alps,omitempty"`
	PaddingLength       *uint16  `json:"padding_length,omitempty"`
}

// ClientProfilePolicy selects required, preferred, and ignored comparison fields.
type ClientProfilePolicy struct {
	MustMatch      []string                  `json:"must_match,omitempty"`
	ShouldMatch    []string                  `json:"should_match,omitempty"`
	IgnoredDynamic []string                  `json:"ignored_dynamic,omitempty"`
	Constraints    []ClientProfileConstraint `json:"constraints,omitempty"`
}

// ClientProfileConstraint describes a typed comparison rule for a profile field.
type ClientProfileConstraint struct {
	Path     string            `json:"path"`
	Operator string            `json:"operator"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Values   []json.RawMessage `json:"values,omitempty"`
}

// ClientProfileExpected contains reference fingerprints and algorithm versions.
type ClientProfileExpected struct {
	JA3                  string `json:"ja3,omitempty"`
	JA3Hash              string `json:"ja3_hash,omitempty"`
	JA4                  string `json:"ja4,omitempty"`
	NormalizedSHA256     string `json:"normalized_sha256,omitempty"`
	NormalizationVersion string `json:"normalization_version,omitempty"`
	MaterializerVersion  string `json:"materializer_version,omitempty"`
	JA3Version           string `json:"ja3_version,omitempty"`
	JA4Version           string `json:"ja4_version,omitempty"`
}

// ClientProfileEngine describes the exporter and materializer compatibility metadata.
type ClientProfileEngine struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Exporter        string `json:"exporter,omitempty"`
	ExporterVersion string `json:"exporter_version,omitempty"`
	Compatibility   string `json:"compatibility,omitempty"`
}

// DecodeClientProfile parses one profile and rejects unknown fields and unsupported major versions.
func DecodeClientProfile(data []byte) (ClientProfile, error) {
	var profile ClientProfile
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return ClientProfile{}, fmt.Errorf("decode client profile: %w", err)
	}
	for _, key := range []string{"schema_version", "id", "version", "name", "profile_type", "fields", "policy", "expected", "engine", "replayability"} {
		if _, ok := topLevel[key]; !ok {
			return ClientProfile{}, fmt.Errorf("decode client profile: required field %q is missing", key)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return ClientProfile{}, fmt.Errorf("decode client profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ClientProfile{}, errors.New("decode client profile: multiple JSON values")
		}
		return ClientProfile{}, fmt.Errorf("decode client profile trailer: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return ClientProfile{}, err
	}
	return profile, nil
}

// Validate checks format-level requirements before a profile can reach the network.
func (p ClientProfile) Validate() error {
	// Preserve validation order so a malformed profile reports the same first error.
	for _, validate := range []func() error{
		p.validateIdentity,
		p.validateProtocolPolicies,
		p.validateReplayModes,
		p.validateEngineMetadata,
		p.validateVersionsAndConstraints,
		p.validateSourceAndMUST,
	} {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateProfileConstraint(constraint ClientProfileConstraint) error {
	if constraint.Path == "" || !strings.HasPrefix(constraint.Path, "/") ||
		strings.TrimSpace(constraint.Operator) == "" {
		return errors.New("client profile constraints require a JSON Pointer path and operator")
	}
	if !validProfilePointerEscapes(constraint.Path) {
		return fmt.Errorf("client profile constraint path %q is not a valid JSON Pointer", constraint.Path)
	}
	switch constraint.Operator {
	case "present":
		if len(constraint.Value) != 0 || len(constraint.Values) != 0 {
			return fmt.Errorf("client profile constraint present for %q does not accept value(s)", constraint.Path)
		}
	case "equals":
		if len(constraint.Value) == 0 || !json.Valid(constraint.Value) || len(constraint.Values) != 0 {
			return fmt.Errorf("client profile constraint equals for %q requires one JSON value", constraint.Path)
		}
	case "one_of":
		if len(constraint.Values) == 0 || len(constraint.Value) != 0 {
			return fmt.Errorf("client profile constraint one_of for %q requires values", constraint.Path)
		}
		for _, value := range constraint.Values {
			if !json.Valid(value) {
				return fmt.Errorf("client profile constraint one_of for %q contains invalid JSON", constraint.Path)
			}
		}
	default:
		return &UnsupportedProfileError{Field: "policy.constraints." + constraint.Operator}
	}
	return nil
}

// Materialize converts the currently supported profile fields to the uTLS spike input.
// Unsupported optional fields are returned explicitly and never silently applied.
func (p ClientProfile) Materialize() (Profile, []string, error) {
	if err := p.Validate(); err != nil {
		return Profile{}, nil, err
	}
	if p.Replayability.Status == "UNSUPPORTED" || p.Replayability.Status == "NON_DETERMINISTIC" {
		return Profile{}, append(
				[]string(nil),
				p.Replayability.Unsupported...), &UnsupportedProfileError{
				Field: "replayability.status",
			}
	}
	if p.ProfileType == "RANDOMIZED" {
		return Profile{}, nil, &UnsupportedProfileError{Field: "randomized_alpn"}
	}
	if p.BasePreset == nil || strings.TrimSpace(p.BasePreset.Client) == "" ||
		strings.TrimSpace(p.BasePreset.Version) == "" {
		return Profile{}, nil, errors.New(
			"client profile requires base_preset client and version for uTLS materialization",
		)
	}
	result := Profile{Preset: p.BasePreset.Client + "-" + p.BasePreset.Version}
	unsupported := append([]string(nil), p.Replayability.Unsupported...)
	if len(p.Fields.ExtensionOrder) != 0 && !contains(p.Replayability.Unsupported, "fields.extension_order") {
		result.ExtensionOrder = append([]uint16(nil), p.Fields.ExtensionOrder...)
	}
	id, err := presetID(result.Preset)
	if err != nil {
		return Profile{}, nil, err
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return Profile{}, nil, fmt.Errorf("load uTLS preset %q: %w", result.Preset, err)
	}
	for _, extension := range spec.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			result.ALPN = append([]string(nil), alpn.AlpnProtocols...)
		}
	}
	unsupported = p.materializeTLSFields(&spec, &result, unsupported)
	unsupported = p.materializeProtocolFields(&result, unsupported)
	if err = applyProfile(&spec, "", result); err != nil {
		return Profile{}, unsupported, fmt.Errorf("validate uTLS profile: %w", err)
	}
	if err := p.validateMaterializedMUST(result, unsupported); err != nil {
		return Profile{}, unsupported, err
	}
	return result, unsupported, nil
}

func countProfileExtensions(extensions []utls.TLSExtension, target uint16) (count int) {
	for _, extension := range extensions {
		id, err := extensionID(extension)
		if err == nil && id == target {
			count++
		}
	}
	return count
}

func profileFieldValues(fields ClientProfileFields, path string) []uint16 {
	switch path {
	case "fields.cipher_suites":
		return fields.CipherSuites
	case "fields.supported_versions":
		return fields.SupportedVersions
	case "fields.supported_groups":
		return fields.SupportedGroups
	case "fields.signature_algorithms":
		return fields.SignatureAlgorithms
	default:
		return nil
	}
}

func supportedMustField(path string) bool {
	switch path {
	case "fields.extension_order",
		"fields.alpn",
		"fields.cipher_suites",
		"fields.supported_versions",
		"fields.supported_groups",
		"fields.signature_algorithms":
		return true
	default:
		return false
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}
