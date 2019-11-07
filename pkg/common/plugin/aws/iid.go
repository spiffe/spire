package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
	// AccessKeyIDVarName env var name for AWS access key ID
	AccessKeyIDVarName = "AWS_ACCESS_KEY_ID"
	// SecretAccessKeyVarName env car name for AWS secret access key
	SecretAccessKeyVarName = "AWS_SECRET_ACCESS_KEY" //nolint: gosec // false positive
)

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

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted AWS IID attestation but an error occurred %s: %s", step, cause)
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
