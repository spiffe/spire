package aws

import (
	"fmt"
)

type InstanceIdentityDocument struct {
	InstanceId string `json:"instanceId" `
	AccountId  string `json:"accountId"`
	Region     string `json:"region"`
}

type IidAttestationData struct {
	Document  string `json:"document"`
	Signature string `json:"signature"`
}

func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted AWS IID attestation but an error occured %s: %s", step, cause)
}
