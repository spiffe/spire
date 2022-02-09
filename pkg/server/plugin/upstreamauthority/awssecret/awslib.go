package awssecret

import (
	"context"
	"fmt"

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
		return "", fmt.Errorf("response or SecretString is nil")
	}

	return *resp.SecretString, nil
}

func newSecretsManagerClient(ctx context.Context, cfg *Configuration, region string) (secretsManagerClient, error) {
	var credsProvider aws.CredentialsProvider
	switch {
	case cfg.AssumeRoleARN != "":
		stsConf := aws.Config{
			Region: region,
		}

		stsClient := sts.NewFromConfig(stsConf)
		credsProvider = stscreds.NewAssumeRoleProvider(stsClient, cfg.AssumeRoleARN)
	case cfg.SecretAccessKey != "" && cfg.AccessKeyID != "":
		credsProvider = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""))
	default:
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
		if err != nil {
			return nil, err
		}

		credsProvider = awsCfg.Credentials
	}

	awsConfig := aws.Config{
		Credentials: credsProvider,
		Region:      region,
	}

	return secretsmanager.NewFromConfig(awsConfig), nil
}
