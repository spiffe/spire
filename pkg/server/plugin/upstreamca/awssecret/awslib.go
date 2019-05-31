package awssecret

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/sts"
)

type secretsManagerClient interface {
	GetSecretValueWithContext(aws.Context, *secretsmanager.GetSecretValueInput, ...request.Option) (*secretsmanager.GetSecretValueOutput, error)
}

func readARN(ctx context.Context, sm secretsManagerClient, arn string) (string, error) {
	resp, err := sm.GetSecretValueWithContext(ctx, &secretsmanager.GetSecretValueInput{
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

func newSecretsManagerClient(config *AWSSecretConfiguration, region string) (secretsManagerClient, error) {
	awsConfig := &aws.Config{
		Region: aws.String(region),
	}

	if config.SecretAccessKey != "" && config.AccessKeyID != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, config.SecurityToken)
	}

	// Optional: Assuming role
	if config.AssumeRoleARN != "" {
		staticsess, err := session.NewSession(&aws.Config{Credentials: awsConfig.Credentials})
		if err != nil {
			return nil, err
		}
		awsConfig.Credentials = credentials.NewCredentials(&stscreds.AssumeRoleProvider{
			Client:   sts.New(staticsess),
			RoleARN:  config.AssumeRoleARN,
			Duration: 5 * time.Minute,
		})
	}

	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	return secretsmanager.New(awsSession), nil
}
