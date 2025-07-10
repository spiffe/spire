package awssecret

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type secretsManagerClient interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func readARN(ctx context.Context, sm secretsManagerClient, arn string) (string, error) {
	resp, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(arn),
	})

	if err != nil { // resp is now filled
		return "", err
	}

	if resp == nil || resp.SecretString == nil {
		return "", errors.New("response or SecretString is nil")
	}

	return *resp.SecretString, nil
}

func newSecretsManagerClient(ctx context.Context, cfg *Configuration, region string) (secretsManagerClient, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	if cfg.SecretAccessKey != "" && cfg.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SecurityToken)))
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	if cfg.AssumeRoleARN != "" {
		awsConfig, err = newAWSAssumeRoleConfig(ctx, region, awsConfig, cfg.AssumeRoleARN)
		if err != nil {
			return nil, err
		}
	}

	return secretsmanager.NewFromConfig(awsConfig), nil
}

func newAWSAssumeRoleConfig(ctx context.Context, region string, awsConf aws.Config, assumeRoleArn string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	stsClient := sts.NewFromConfig(awsConf)
	opts = append(opts, config.WithCredentialsProvider(aws.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(stsClient, assumeRoleArn))),
	)

	return config.LoadDefaultConfig(ctx, opts...)
}
