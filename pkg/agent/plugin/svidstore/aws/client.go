package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type SecretsManagerClient interface {
	DescribeSecret(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error)
	CreateSecret(input *secretsmanager.CreateSecretInput) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error)
}

func createSecretManagerClient(secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error) {
	var awsConf *aws.Config
	if secretAccessKey != "" && accessKeyID != "" {
		creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		awsConf = &aws.Config{Credentials: creds, Region: aws.String(region)}
	} else {
		awsConf = &aws.Config{Region: aws.String(region)}
	}
	sess, err := session.NewSession(awsConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return secretsmanager.New(sess), nil
}
