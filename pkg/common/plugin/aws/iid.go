package aws

import (
	"fmt"
	"net/url"
	"path"
)

type InstanceIdentityDocument struct {
	InstanceId string `json:"instanceId" `
	AccountId  string `json:"accountId"`
	Region     string `json:"region"`
}

type IIDAttestationData struct {
	Document  string `json:"document"`
	Signature string `json:"signature"`
}

func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted AWS IID attestation but an error occured %s: %s", step, cause)
}

func IIDAgentID(trustDomain, accountID, region, instanceID string) string {
	id := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "aws_iid", accountID, region, instanceID),
	}
	return id.String()
}
