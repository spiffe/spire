package tpmdevid

import (
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const PluginName = "tpm_devid"

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

func ValidateGlobalConfig(c *plugin.ConfigureRequest_GlobalConfig) error {
	if c == nil {
		return status.Error(codes.InvalidArgument, "global configuration is required")
	}

	if c.TrustDomain == "" {
		return status.Error(codes.InvalidArgument, "trust_domain is required")
	}
	return nil
}
