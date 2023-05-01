package aws

import (
	"github.com/zeebo/errs"
)

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
)

var (
	IidErrorClass = errs.Class("aws-iid")
	iidError      = IidErrorClass
)

// IIDAttestationData AWS IID attestation data
type IIDAttestationData struct {
	Document         string `json:"document"`
	Signature        string `json:"signature"`
	SignatureRSA2048 string `json:"rsa2048"`
}

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return iidError.New("attempted attestation but an error occurred %s: %w", step, cause)
}
