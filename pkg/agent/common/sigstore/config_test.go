package sigstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				PublicKeyPaths:     []string{"test-public-key"},
				RegistryReferrers:  new(true),
				SkippedImages:      []string{"registry/image@sha256:examplehash"},
				RekorURL:           new("https://test.dev"),
				IgnoreSCT:          new(true),
				IgnoreTlog:         new(true),
				IgnoreAttestations: new(true),
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
				PublicKeyPaths:     []string{"test-public-key"},
				RegistryReferrers:  true,
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

func TestHCLConfigValidate(t *testing.T) {
	invalidKeyPath := filepath.Join(t.TempDir(), "invalid.pub")
	require.NoError(t, os.WriteFile(invalidKeyPath, []byte("\n "), 0o600))
	missingKeyPath := filepath.Join(t.TempDir(), "missing.pub")
	_, missingKeyErr := os.ReadFile(missingKeyPath)

	for _, tt := range []struct {
		name string
		hcl  *HCLConfig
		err  string
	}{
		{name: "keyless", hcl: &HCLConfig{AllowedIdentities: map[string][]string{"issuer": {"subject"}}}},
		{name: "public keys", hcl: &HCLConfig{PublicKeyPaths: []string{newPublicKeyFile(t)}}},
		{
			name: "public keys and allowed identities",
			hcl:  &HCLConfig{PublicKeyPaths: []string{"key"}, AllowedIdentities: map[string][]string{"issuer": {"subject"}}},
			err:  "sigstore public_key_paths and allowed_identities cannot be used together",
		},
		{
			name: "invalid public key",
			hcl:  &HCLConfig{PublicKeyPaths: []string{newPublicKeyFile(t), invalidKeyPath}},
			err:  fmt.Sprintf("sigstore public_key_paths: failed to parse public key %q: PEM decoding failed", invalidKeyPath),
		},
		{
			name: "missing public key file",
			hcl:  &HCLConfig{PublicKeyPaths: []string{missingKeyPath}},
			err:  fmt.Sprintf("sigstore public_key_paths: failed to read public key %q: %v", missingKeyPath, missingKeyErr),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hcl.Validate()
			if tt.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.err)
		})
	}
}
