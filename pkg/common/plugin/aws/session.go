package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

// SessionConfig is a common config for AWS session config.
type SessionConfig struct {
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
}

func (cfg *SessionConfig) Validate(defaultAccessKeyID, defaultSecretAccessKey string) error {
	if cfg.AccessKeyID == "" {
		cfg.AccessKeyID = defaultAccessKeyID
	}

	if cfg.SecretAccessKey == "" {
		cfg.SecretAccessKey = defaultSecretAccessKey
	}

	switch {
	case cfg.AccessKeyID != "" && cfg.SecretAccessKey == "":
		return iidError.New("configuration missing secret access key, but has access key id")
	case cfg.AccessKeyID == "" && cfg.SecretAccessKey != "":
		return iidError.New("configuration missing access key id, but has secret access key")
	}
	return nil
}

// newAWSSession create an AWS Session from the config and given region
func newAWSSession(accessKeyID, secretAccessKey, region string) (*session.Session, error) {
	var awsConf *aws.Config
	if secretAccessKey != "" && accessKeyID != "" {
		creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		awsConf = &aws.Config{Credentials: creds, Region: &region}
	} else {
		awsConf = &aws.Config{Region: &region}
	}
	return session.NewSession(awsConf)
}
