package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SessionConfig is a common config for AWS session config.
type SessionConfig struct {
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
	AssumeRole      string `hcl:"assume_role"`
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

// newAWSSession create an AWS config from the credentials and given region
func newAWSConfig(accessKeyID, secretAccessKey, region, assumeRoleArn string) aws.Config {
	var credsProvider aws.CredentialsProvider
	switch {
	case assumeRoleArn != "":
		stsConf := aws.Config{
			Region: region,
		}

		stsClient := sts.NewFromConfig(stsConf)
		credsProvider = stscreds.NewAssumeRoleProvider(stsClient, assumeRoleArn)
	case secretAccessKey != "" && accessKeyID != "":
		credsProvider = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""))
	}

	return aws.Config{
		Credentials: credsProvider,
		Region:      region,
	}
}
