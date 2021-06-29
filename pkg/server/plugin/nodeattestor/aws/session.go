package aws

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SessionConfig is a common config for AWS session config.
type SessionConfig struct {
	AccessKeyID           string `hcl:"access_key_id"`
	SecretAccessKey       string `hcl:"secret_access_key"`
	AssumeRoleArnTemplate string `hcl:"assume_role_arn_template"`
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
		return status.Error(codes.InvalidArgument, "configuration missing secret access key, but has access key id")
	case cfg.AccessKeyID == "" && cfg.SecretAccessKey != "":
		return status.Error(codes.InvalidArgument, "configuration missing access key id, but has secret access key")
	}
	return nil
}

// newAWSSession create an AWS Session from the config and given region
func newAWSSession(accessKeyID, secretAccessKey, region, asssumeRoleArn string) (*session.Session, error) {
	var awsConf *aws.Config
	if secretAccessKey != "" && accessKeyID != "" {
		creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		awsConf = &aws.Config{Credentials: creds, Region: &region}
	} else {
		awsConf = &aws.Config{Region: &region}
	}

	// Optional: Assuming role
	if asssumeRoleArn != "" {
		staticsess, err := session.NewSession(&aws.Config{Credentials: awsConf.Credentials})
		if err != nil {
			return nil, err
		}

		awsConf.Credentials = credentials.NewCredentials(&stscreds.AssumeRoleProvider{
			Client:   sts.New(staticsess),
			RoleARN:  asssumeRoleArn,
			Duration: 15 * time.Minute,
		})
	}

	return session.NewSession(awsConf)
}
