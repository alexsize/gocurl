package utlsengine

import "encoding/json"

func checkNormalizedProfileExpectation(profile ClientProfile, actual Fingerprint, result *ProfileCheckResult) bool {
	unsupported := false
	if profile.Expected.NormalizedSHA256 != "" {
		if profile.Expected.NormalizationVersion != TLSNormalizationVersion {
			unsupported = true
			result.Diffs = append(result.Diffs, ProfileDifference{
				Path: "expected.normalization_version", Expected: profile.Expected.NormalizationVersion,
				Actual: actual.NormalizationVersion, Policy: "UNSUPPORTED: normalization version is not supported",
			})
		} else if actual.NormalizationError != "" {
			unsupported = true
			result.Diffs = append(result.Diffs, ProfileDifference{
				Path: "expected.normalized_sha256", Expected: profile.Expected.NormalizedSHA256,
				Actual: nil, Policy: "UNSUPPORTED: " + actual.NormalizationError,
			})
		} else if profile.Expected.NormalizedSHA256 != actual.NormalizedSHA256 {
			result.Diffs = append(result.Diffs, ProfileDifference{
				Path: "expected.normalized_sha256", Expected: profile.Expected.NormalizedSHA256,
				Actual: actual.NormalizedSHA256, Policy: "MUST",
			})
		}
	}
	return unsupported
}

func checkProfileConstraints(profile ClientProfile, actual Fingerprint, result *ProfileCheckResult) bool {
	unsupported := false
	if len(profile.Policy.Constraints) > 0 {
		var normalized any
		if actual.NormalizationError != "" || len(actual.normalizedDocument) == 0 {
			unsupported = true
			for _, constraint := range profile.Policy.Constraints {
				result.Diffs = append(result.Diffs, ProfileDifference{
					Path: constraint.Path, Expected: constraintExpectation(constraint),
					Policy: "UNSUPPORTED: normalized ClientHello document is unavailable",
				})
			}
		} else if err := json.Unmarshal(actual.normalizedDocument, &normalized); err != nil {
			unsupported = true
			for _, constraint := range profile.Policy.Constraints {
				result.Diffs = append(result.Diffs, ProfileDifference{
					Path: constraint.Path, Expected: constraintExpectation(constraint),
					Policy: "UNSUPPORTED: invalid normalized ClientHello document",
				})
			}
		} else {
			for _, constraint := range profile.Policy.Constraints {
				value, exists := valueAtJSONPointer(normalized, constraint.Path)
				if profileConstraintMatches(constraint, value, exists) {
					continue
				}
				observed := map[string]any{"exists": exists}
				if exists {
					observed["value"] = value
				}
				result.Diffs = append(result.Diffs, ProfileDifference{
					Path:     constraint.Path,
					Expected: constraintExpectation(constraint),
					Actual:   observed,
					Policy:   "CONSTRAINT",
				})
			}
		}
	}
	return unsupported
}
