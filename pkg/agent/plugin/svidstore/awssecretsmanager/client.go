package awssecretsmanager

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsManagerClient interface {
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	RestoreSecret(context.Context, *secretsmanager.RestoreSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.RestoreSecretOutput, error)
}

func createSecretManagerClient(ctx context.Context, secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)
	if err != nil {
		return nil, err
	}

	if secretAccessKey != "" && accessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
	}
	return secretsmanager.NewFromConfig(cfg), nil
}
