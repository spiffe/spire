package aws

import "fmt"

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
)

// IIDAttestationData AWS IID attestation data
type IIDAttestationData struct {
	Document         string `json:"document"`
	Signature        string `json:"signature"`
	SignatureRSA2048 string `json:"rsa2048"`
}

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("aws-iid: attempted attestation but an error occurred %s: %w", step, cause)
}
