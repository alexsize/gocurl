package config

import (
	"strings"
	"testing"
)

func TestParseConfigRejectsPostQuantumProfileAndHTTP3(t *testing.T) {
	for _, experiment := range []string{"pq", "pq:", "pq:1", "pq:0"} {
		for _, mode := range []string{"profile", "http3"} {
			t.Run(mode+"/"+experiment, func(t *testing.T) {
				args := []string{"--experiment=" + experiment}
				if mode == "profile" {
					args = append(args, "--tls-profile", profileFixturePath("profile-v1-valid.json"))
				} else {
					args = append(args, "--http3")
				}
				args = append(args, "https://127.0.0.1:1/")
				_, err := ParseConfig(args)
				if err == nil || !strings.Contains(err.Error(), "post-quantum") {
					t.Fatalf("ParseConfig(%v) = %v, want post-quantum compatibility error", args, err)
				}
			})
		}
	}
}
