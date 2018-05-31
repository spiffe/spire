package gcp

import (
	"fmt"
)

type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type IdentityToken struct {
	Issuer          string `json:"iss"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
	Audience        string `json:"aud"`
	Subject         string `json:"sub"`
	AuthorizedParty string `json:"azp"`
	Google          Google `json:"google"`
}

type Google struct {
	ComputeEngine ComputeEngine `json:"compute_engine"`
}

type ComputeEngine struct {
	ProjectID                 string `json:"project_id"`
	ProjectNumber             int64  `json:"project_number"`
	Zone                      string `json:"zone"`
	InstanceID                string `json:"instance_id"`
	InstanceName              string `json:"instance_name"`
	InstanceCreationTimestamp int64  `json:"instance_creation_timestamp"`
}

type IIDAttestedData struct {
	Header    string `json:"header"`
	Token     string `json:"payload"`
	Signature []byte `json:"signature"`
}

func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted GCP IID attestation but an error occured %s: %s", step, cause)
}
