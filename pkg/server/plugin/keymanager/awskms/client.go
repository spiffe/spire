package awskms

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type kmsClient interface {
	CreateKeyWithContext(aws.Context, *kms.CreateKeyInput, ...request.Option) (*kms.CreateKeyOutput, error)
	DescribeKeyWithContext(aws.Context, *kms.DescribeKeyInput, ...request.Option) (*kms.DescribeKeyOutput, error)
	CreateAliasWithContext(aws.Context, *kms.CreateAliasInput, ...request.Option) (*kms.CreateAliasOutput, error)
	UpdateAliasWithContext(aws.Context, *kms.UpdateAliasInput, ...request.Option) (*kms.UpdateAliasOutput, error)
	GetPublicKeyWithContext(aws.Context, *kms.GetPublicKeyInput, ...request.Option) (*kms.GetPublicKeyOutput, error)
	ListAliasesWithContext(aws.Context, *kms.ListAliasesInput, ...request.Option) (*kms.ListAliasesOutput, error)
	ScheduleKeyDeletionWithContext(aws.Context, *kms.ScheduleKeyDeletionInput, ...request.Option) (*kms.ScheduleKeyDeletionOutput, error)
	SignWithContext(aws.Context, *kms.SignInput, ...request.Option) (*kms.SignOutput, error)
}

func newKMSClient(c *Config) (kmsClient, error) {
	awsConfig := &aws.Config{
		Region: aws.String(c.Region),
	}
	if c.SecretAccessKey != "" && c.AccessKeyID != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(c.AccessKeyID, c.SecretAccessKey, "")
	}

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	return kms.New(s), nil
}
