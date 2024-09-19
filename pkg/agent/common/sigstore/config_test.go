package sigstore

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestNewConfigFromHCL(t *testing.T) {
	tests := []struct {
		name string
		hcl  *HCLConfig
		want *Config
	}{
		{
			name: "complete sigstore configuration",
			hcl: &HCLConfig{
				AllowedIdentities: map[string][]string{
					"test-issuer-1": {"*@example.com", "subject@otherdomain.com"},
					"test-issuer-2": {"domain/ci.yaml@refs/tags/*"},
				},
				SkippedImages:      []string{"registry/image@sha256:examplehash"},
				RekorURL:           strPtr("https://test.dev"),
				IgnoreSCT:          boolPtr(true),
				IgnoreTlog:         boolPtr(true),
				IgnoreAttestations: boolPtr(true),
				RegistryCredentials: map[string]*RegistryCredential{
					"registry": {
						Username: "user",
						Password: "pass",
					},
				},
			},
			want: &Config{
				AllowedIdentities: map[string][]string{
					"test-issuer-1": {"*@example.com", "subject@otherdomain.com"},
					"test-issuer-2": {"domain/ci.yaml@refs/tags/*"},
				},
				SkippedImages:      map[string]struct{}{"registry/image@sha256:examplehash": {}},
				RekorURL:           "https://test.dev",
				IgnoreSCT:          true,
				IgnoreTlog:         true,
				IgnoreAttestations: true,
				RegistryCredentials: map[string]*RegistryCredential{
					"registry": {
						Username: "user",
						Password: "pass",
					},
				},
				Logger: hclog.NewNullLogger(),
			},
		},
		{
			name: "empty sigstore configuration",
			hcl:  &HCLConfig{},
			want: &Config{
				AllowedIdentities:   map[string][]string{},
				SkippedImages:       map[string]struct{}{},
				RekorURL:            "",
				IgnoreSCT:           false,
				IgnoreTlog:          false,
				IgnoreAttestations:  false,
				RegistryCredentials: nil,
				Logger:              hclog.NewNullLogger(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hclog.NewNullLogger()
			got := NewConfigFromHCL(tt.hcl, log)
			assert.Equal(t, tt.want, got)
		})
	}
}

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
