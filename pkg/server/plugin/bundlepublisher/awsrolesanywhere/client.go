package awsrolesanywhere

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
)

type rolesAnywhere interface {
	UpdateTrustAnchor(ctx context.Context, params *rolesanywhere.UpdateTrustAnchorInput, optFns ...func(*rolesanywhere.Options)) (*rolesanywhere.UpdateTrustAnchorOutput, error)
}

func newAWSConfig(ctx context.Context, c *Config) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.Region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	if c.SecretAccessKey != "" && c.AccessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")
	}

	return cfg, nil
}

func newRolesAnywhereClient(c aws.Config) (rolesAnywhere, error) {
	return rolesanywhere.NewFromConfig(c), nil
}
