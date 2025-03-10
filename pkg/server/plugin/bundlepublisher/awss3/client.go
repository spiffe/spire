package awss3

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type simpleStorageService interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
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

	if c.Endpoint != "" {
		cfg.BaseEndpoint = aws.String(c.Endpoint)
	}

	return cfg, nil
}

func newS3Client(c aws.Config) (simpleStorageService, error) {
	options := func(options *s3.Options) {}
	if c.BaseEndpoint != nil && *c.BaseEndpoint != "" {
		options = func(options *s3.Options) {
			options.UsePathStyle = true
			options.BaseEndpoint = c.BaseEndpoint
		}
	}
	return s3.NewFromConfig(c, options), nil
}
