package utlsengine

import (
	"errors"
	"fmt"
	"strings"
)

func (p ClientProfile) validateIdentity() error {
	if p.SchemaVersion != ProfileSchemaVersion {
		return fmt.Errorf(
			"client profile schema_version %q is unsupported; expected %q",
			p.SchemaVersion,
			ProfileSchemaVersion,
		)
	}
	if strings.TrimSpace(p.ID) == "" || p.Version < 1 || strings.TrimSpace(p.Name) == "" {
		return errors.New("client profile requires non-empty id/name and version >= 1")
	}
	switch p.ProfileType {
	case "PRESET", "OBSERVED", "CUSTOM", "RANDOMIZED":
	default:
		return fmt.Errorf("client profile profile_type %q is invalid", p.ProfileType)
	}
	return nil
}

func (p ClientProfile) validateProtocolPolicies() error {
	if p.Fields.ALPNPolicy != "" && p.Fields.ALPNPolicy != "PROFILE" && p.Fields.ALPNPolicy != "DOWNSTREAM" &&
		p.Fields.ALPNPolicy != "INTERSECTION" && p.Fields.ALPNPolicy != "CUSTOM" {
		return fmt.Errorf("client profile fields.alpn_policy %q is invalid", p.Fields.ALPNPolicy)
	}
	if p.Fields.ALPNPolicy == "CUSTOM" && len(p.Fields.CustomALPN) == 0 {
		return errors.New("client profile fields.custom_alpn is required when alpn_policy is CUSTOM")
	}
	if p.Fields.ALPSPolicy != "" && p.Fields.ALPSPolicy != "PROFILE" && p.Fields.ALPSPolicy != "DOWNSTREAM" &&
		p.Fields.ALPSPolicy != "INTERSECTION" && p.Fields.ALPSPolicy != "CUSTOM" {
		return fmt.Errorf("client profile fields.alps_policy %q is invalid", p.Fields.ALPSPolicy)
	}
	return nil
}

func (p ClientProfile) validateReplayModes() error {
	if p.Replayability.Status != "REPLAYABLE" && p.Replayability.Status != "PARTIAL" &&
		p.Replayability.Status != "UNSUPPORTED" && p.Replayability.Status != "NON_DETERMINISTIC" {
		return fmt.Errorf("client profile replayability.status %q is invalid", p.Replayability.Status)
	}
	if p.ProfileMode != "" && p.ProfileMode != "STRICT" && p.ProfileMode != "ADAPTIVE" {
		return fmt.Errorf("client profile profile_mode %q is invalid", p.ProfileMode)
	}
	if p.ProfileType == "RANDOMIZED" && p.RandomizedALPN != "" && p.RandomizedALPN != "AUTO" &&
		p.RandomizedALPN != "REQUIRED" && p.RandomizedALPN != "DISABLED" {
		return fmt.Errorf("client profile randomized_alpn %q is invalid", p.RandomizedALPN)
	}
	if p.ProfileType == "RANDOMIZED" && p.RandomizedALPN == "" {
		return errors.New("client profile randomized_alpn is required for RANDOMIZED profiles")
	}
	return nil
}

func (p ClientProfile) validateEngineMetadata() error {
	if strings.TrimSpace(p.Engine.Name) == "" || strings.TrimSpace(p.Engine.Version) == "" {
		return errors.New("client profile requires engine name and version")
	}
	for _, entry := range p.Replayability.Unsupported {
		if strings.TrimSpace(entry) == "" {
			return errors.New("client profile unsupported entries must not be empty")
		}
	}
	return nil
}

func (p ClientProfile) validateVersionsAndConstraints() error {
	seenVersions := make(map[uint16]struct{}, len(p.Fields.SupportedVersions))
	for _, version := range p.Fields.SupportedVersions {
		if version < 0x0301 || version > 0x0304 {
			return fmt.Errorf("client profile supported_versions contains unsupported TLS version 0x%04x", version)
		}
		if _, ok := seenVersions[version]; ok {
			return fmt.Errorf("client profile supported_versions contains duplicate TLS version 0x%04x", version)
		}
		seenVersions[version] = struct{}{}
	}
	for _, constraint := range p.Policy.Constraints {
		if err := validateProfileConstraint(constraint); err != nil {
			return err
		}
	}
	return nil
}

func (p ClientProfile) validateSourceAndMUST() error {
	if p.Source != nil && (strings.TrimSpace(p.Source.ObservationID) == "" || strings.TrimSpace(p.Source.JA3) == "" ||
		strings.TrimSpace(p.Source.JA3Hash) == "" || strings.TrimSpace(p.Source.JA4) == "" ||
		strings.TrimSpace(p.Source.NormalizedSHA256) == "" || strings.TrimSpace(p.Source.NormalizationVersion) == "") {
		return errors.New("client profile source requires observation and fingerprint metadata")
	}
	for _, path := range p.Policy.MustMatch {
		if !supportedMustField(path) {
			return &UnsupportedProfileError{Field: path}
		}
	}
	return nil
}

func validProfilePointerEscapes(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] == '~' {
			i++
			if i >= len(path) || path[i] != '0' && path[i] != '1' {
				return false
			}
		}
	}
	return true
}
