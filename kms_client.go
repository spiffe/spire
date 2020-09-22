package kms

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
	GetPublicKeyWithContext(aws.Context, *kms.GetPublicKeyInput, ...request.Option) (*kms.GetPublicKeyOutput, error)
	ListKeysWithContext(aws.Context, *kms.ListKeysInput, ...request.Option) (*kms.ListKeysOutput, error)
	ScheduleKeyDeletionWithContext(aws.Context, *kms.ScheduleKeyDeletionInput, ...request.Option) (*kms.ScheduleKeyDeletionOutput, error)
	SignWithContext(aws.Context, *kms.SignInput, ...request.Option) (*kms.SignOutput, error)
}

func newKMSClient(c *Config) (*kms.KMS, error) {
	creds := credentials.NewStaticCredentials(c.AccessKeyID, c.SecretAccessKey, "")
	awsConf := &aws.Config{Credentials: creds, Region: aws.String(c.Region)}
	s, err := session.NewSession(awsConf)
	if err != nil {
		return nil, err
	}

	return kms.New(s), nil
}
