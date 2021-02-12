package devid

import (
	"fmt"

	"github.com/spiffe/spire/proto/spire/common/plugin"
)

const PluginName = "devid"

type AttestationRequest struct {
	DevIDCert []byte
	DevIDPub  []byte

	EKCert []byte
	EKPub  []byte

	AKPub []byte

	CertifiedDevID         []byte
	CertificationSignature []byte
}

type ChallengeRequest struct {
	DevID          []byte
	CredActivation *CredActivation
}

type CredActivation struct {
	Credential []byte
	Secret     []byte
}

type ChallengeResponse struct {
	DevID          []byte
	CredActivation []byte
}

func Error(format string, args ...interface{}) error {
	return fmt.Errorf("devid: "+format, args...)
}

func ValidateGlobalConfig(c *plugin.ConfigureRequest_GlobalConfig) error {
	if c == nil {
		return Error("global configuration is required")
	}

	if c.TrustDomain == "" {
		return Error("trust_domain is required")
	}
	return nil
}
