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
				PublicKeys:         []string{"test-public-key"},
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
				PublicKeys:         []string{"test-public-key"},
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
	for _, tt := range []struct {
		name string
		hcl  *HCLConfig
		err  string
	}{
		{name: "keyless", hcl: &HCLConfig{AllowedIdentities: map[string][]string{"issuer": {"subject"}}}},
		{name: "public keys", hcl: &HCLConfig{PublicKeys: []string{newPublicKeyPEM(t)}}},
		{
			name: "public keys and allowed identities",
			hcl:  &HCLConfig{PublicKeys: []string{"key"}, AllowedIdentities: map[string][]string{"issuer": {"subject"}}},
			err:  "sigstore public_keys and allowed_identities cannot be used together",
		},
		{
			name: "invalid public key",
			hcl:  &HCLConfig{PublicKeys: []string{newPublicKeyPEM(t), "\n "}},
			err:  "sigstore public_keys: failed to parse public key 1: PEM decoding failed",
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
