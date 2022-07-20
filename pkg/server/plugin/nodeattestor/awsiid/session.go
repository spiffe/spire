package awsiid

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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
func newAWSConfig(ctx context.Context, accessKeyID, secretAccessKey, region, assumeRoleArn string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	if secretAccessKey != "" && accessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")))
	}

	conf, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	if assumeRoleArn == "" {
		return conf, nil
	}

	return newAWSAssumeRoleConfig(ctx, region, conf, assumeRoleArn)
}

func newAWSAssumeRoleConfig(ctx context.Context, region string, stsConf aws.Config, assumeRoleArn string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	stsClient := sts.NewFromConfig(stsConf)
	opts = append(opts, config.WithCredentialsProvider(aws.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(stsClient, assumeRoleArn))),
	)

	return config.LoadDefaultConfig(ctx, opts...)
}
