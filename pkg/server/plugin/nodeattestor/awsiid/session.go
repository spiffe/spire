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
	AccessKeyID          string `hcl:"access_key_id"`
	SecretAccessKey      string `hcl:"secret_access_key"`
	AssumeRole           string `hcl:"assume_role"`
	Partition            string `hcl:"partition"`
	WebIdentityRoleARN   string `hcl:"web_identity_role_arn"`
	WebIdentityTokenFile string `hcl:"web_identity_token_file"`
}

func (cfg *SessionConfig) Validate(defaultAccessKeyID, defaultSecretAccessKey string) error {
	// A configured web identity role wins over the default access keys from the environment.
	if cfg.WebIdentityRoleARN == "" {
		if cfg.AccessKeyID == "" {
			cfg.AccessKeyID = defaultAccessKeyID
		}

		if cfg.SecretAccessKey == "" {
			cfg.SecretAccessKey = defaultSecretAccessKey
		}
	}

	if cfg.Partition == "" {
		cfg.Partition = defaultPartition
	}

	switch {
	case cfg.AccessKeyID != "" && cfg.SecretAccessKey == "":
		return status.Error(codes.InvalidArgument, "configuration missing secret access key, but has access key id")
	case cfg.AccessKeyID == "" && cfg.SecretAccessKey != "":
		return status.Error(codes.InvalidArgument, "configuration missing access key id, but has secret access key")
	case cfg.WebIdentityRoleARN != "" && cfg.WebIdentityTokenFile == "":
		return status.Error(codes.InvalidArgument, "configuration missing web identity token file, but has web identity role ARN")
	case cfg.WebIdentityRoleARN == "" && cfg.WebIdentityTokenFile != "":
		return status.Error(codes.InvalidArgument, "configuration missing web identity role ARN, but has web identity token file")
	case cfg.WebIdentityRoleARN != "" && cfg.AccessKeyID != "":
		return status.Error(codes.InvalidArgument, "configuration has both an access key id and a web identity role ARN, only one can be used")
	}
	return nil
}

// newWebIdentitySTSClient creates the STS client used to assume the web identity role. Tests replace it.
var newWebIdentitySTSClient = func(conf aws.Config) stscreds.AssumeRoleWithWebIdentityAPIClient {
	return sts.NewFromConfig(conf)
}

// newAWSConfig creates an AWS config from the session config and given region
func newAWSConfig(ctx context.Context, sessionConfig *SessionConfig, region, assumeRoleArn string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	switch {
	case sessionConfig.SecretAccessKey != "" && sessionConfig.AccessKeyID != "":
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(sessionConfig.AccessKeyID, sessionConfig.SecretAccessKey, "")))
	case sessionConfig.WebIdentityRoleARN != "":
		// AssumeRoleWithWebIdentity is not signed, so the STS client needs no credentials.
		stsConf, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithCredentialsProvider(aws.AnonymousCredentials{}))
		if err != nil {
			return aws.Config{}, err
		}
		opts = append(opts, config.WithCredentialsProvider(aws.NewCredentialsCache(
			stscreds.NewWebIdentityRoleProvider(newWebIdentitySTSClient(stsConf), sessionConfig.WebIdentityRoleARN,
				stscreds.IdentityTokenFile(sessionConfig.WebIdentityTokenFile)))),
		)
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
