package sigstore

import "github.com/hashicorp/go-hclog"

// Config holds configuration for the ImageVerifier.
type Config struct {
	RekorURL            string
	RegistryCredentials map[string]*RegistryCredential

	AllowedIdentities  map[string][]string
	SkippedImages      map[string]struct{}
	IgnoreSCT          bool
	IgnoreTlog         bool
	IgnoreAttestations bool

	Logger hclog.Logger
}

func NewConfig() *Config {
	return &Config{
		AllowedIdentities: make(map[string][]string),
		SkippedImages:     make(map[string]struct{}),
	}
}

type HCLConfig struct {
	// AllowedIdentities is a list of identities (issuer and subjects) that must match for the signature to be valid.
	AllowedIdentities map[string][]string `hcl:"allowed_identities" json:"allowed_identities"`

	// SkippedImages is a list of images that should skip sigstore verification
	SkippedImages []string `hcl:"skipped_images" json:"skipped_images"`

	// RekorURL is the URL for the Rekor transparency log server to use for verifying entries.
	RekorURL *string `hcl:"rekor_url,omitempty" json:"rekor_url,omitempty"`

	// IgnoreSCT specifies whether to bypass the requirement for a Signed Certificate Timestamp (SCT) during verification.
	// An SCT is proof of inclusion in a Certificate Transparency log.
	IgnoreSCT *bool `hcl:"ignore_sct,omitempty" json:"ignore_sct,omitempty"`

	// IgnoreTlog specifies whether to bypass the requirement for transparency log verification during signature validation.
	IgnoreTlog *bool `hcl:"ignore_tlog,omitempty" json:"ignore_tlog,omitempty"`

	// IgnoreAttestations specifies whether to bypass the image attestations verification.
	IgnoreAttestations *bool `hcl:"ignore_attestations,omitempty" json:"ignore_attestations,omitempty"`

	// RegistryCredentials is a map of credentials keyed by registry URL
	RegistryCredentials map[string]*RegistryCredential `hcl:"registry_credentials,omitempty" json:"registry_credentials,omitempty"`
}

type RegistryCredential struct {
	Username string `hcl:"username,omitempty" json:"username,omitempty"`
	Password string `hcl:"password,omitempty" json:"password,omitempty"`
}

func NewConfigFromHCL(hclConfig *HCLConfig, log hclog.Logger) *Config {
	config := NewConfig()
	config.Logger = log

	if hclConfig.AllowedIdentities != nil {
		config.AllowedIdentities = hclConfig.AllowedIdentities
	}

	if hclConfig.SkippedImages != nil {
		config.SkippedImages = make(map[string]struct{})
		for _, image := range hclConfig.SkippedImages {
			config.SkippedImages[image] = struct{}{}
		}
	}

	if hclConfig.RekorURL != nil {
		config.RekorURL = *hclConfig.RekorURL
	}

	if hclConfig.IgnoreSCT != nil {
		config.IgnoreSCT = *hclConfig.IgnoreSCT
	}

	if hclConfig.IgnoreTlog != nil {
		config.IgnoreTlog = *hclConfig.IgnoreTlog
	}

	if hclConfig.IgnoreAttestations != nil {
		config.IgnoreAttestations = *hclConfig.IgnoreAttestations
	}

	if hclConfig.RegistryCredentials != nil {
		m := make(map[string]*RegistryCredential)
		for k, v := range hclConfig.RegistryCredentials {
			m[k] = &RegistryCredential{
				Username: v.Username,
				Password: v.Password,
			}
		}
		config.RegistryCredentials = m
	}

	return config
}
