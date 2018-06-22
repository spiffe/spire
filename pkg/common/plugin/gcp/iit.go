package gcp

import (
	"fmt"
	"net/url"
	"path"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	PluginName = "gcp_iit"
)

type IdentityToken struct {
	jwt.StandardClaims

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

func AttestationStepError(step string, cause error) error {
	const prefix = "Attempted GCP IIT attestation but an error occured "
	if cause == nil {
		return fmt.Errorf(prefix+"%s", step)
	}
	return fmt.Errorf(prefix+"%s: %s", step, cause)
}

func MakeSpiffeID(trustDomain, gcpAccountID, gcpInstanceID string) string {
	spiffePath := path.Join("spire", "agent", PluginName, gcpAccountID, gcpInstanceID)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   spiffePath,
	}
	return id.String()
}
