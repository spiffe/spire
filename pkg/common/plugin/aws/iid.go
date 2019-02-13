package aws

import (
	"bytes"
	"fmt"
	"net/url"
	"text/template"

	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"))

type agentPathTemplateData struct {
	InstanceIdentityDocument
	PluginName  string
	TrustDomain string
}

// InstanceIdentityDocument AWS IID struct
type InstanceIdentityDocument struct {
	InstanceID string `json:"instanceId" `
	AccountID  string `json:"accountId"`
	Region     string `json:"region"`
}

// IIDAttestationData AWS IID attestation data
type IIDAttestationData struct {
	Document  string `json:"document"`
	Signature string `json:"signature"`
}

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted AWS IID attestation but an error occured %s: %s", step, cause)
}

// MakeSpiffeID create spiffe ID from IID data
func MakeSpiffeID(trustDomain string, agentPathTemplate *template.Template, doc InstanceIdentityDocument) (*url.URL, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		InstanceIdentityDocument: doc,
		PluginName:               PluginName,
	}); err != nil {
		return nil, err
	}

	return idutil.AgentURI(trustDomain, agentPath.String()), nil
}
