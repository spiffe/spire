package aws

import (
	"bytes"
	"fmt"
	"net/url"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
	// AccessKeyIDVarName env var name for AWS access key ID
	AccessKeyIDVarName = "AWS_ACCESS_KEY_ID"
	// SecretAccessKeyVarName env car name for AWS secret access key
	SecretAccessKeyVarName = "AWS_SECRET_ACCESS_KEY"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"))

type agentPathTemplateData struct {
	InstanceIdentityDocument
	PluginName  string
	TrustDomain string
	Tags        InstanceTags
}

// SessionConfig is a common config for AWS session config.
type SessionConfig struct {
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
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

type InstanceTags map[string]string

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted AWS IID attestation but an error occurred %s: %s", step, cause)
}

// MakeSpiffeID create spiffe ID from IID data
func MakeSpiffeID(trustDomain string, agentPathTemplate *template.Template, doc InstanceIdentityDocument, tags InstanceTags) (*url.URL, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		InstanceIdentityDocument: doc,
		PluginName:               PluginName,
		Tags:                     tags,
	}); err != nil {
		return nil, err
	}

	return idutil.AgentURI(trustDomain, agentPath.String()), nil
}

// NewAWSSession create an AWS Session from the config and given region
func NewAWSSession(accessKeyID, secretAccessKey, region string) (*session.Session, error) {
	var awsConf *aws.Config
	if secretAccessKey != "" && accessKeyID != "" {
		creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		awsConf = &aws.Config{Credentials: creds, Region: &region}
	} else {
		awsConf = &aws.Config{Region: &region}
	}
	return session.NewSession(awsConf)
}
