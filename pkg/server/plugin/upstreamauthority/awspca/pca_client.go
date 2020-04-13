package awspca

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/aws/aws-sdk-go/service/sts"
)

// PCAClient provides an interface which can be mocked to test
// the functionality of the plugin.
type PCAClient interface {
	DescribeCertificateAuthorityWithContext(aws.Context, *acmpca.DescribeCertificateAuthorityInput, ...request.Option) (*acmpca.DescribeCertificateAuthorityOutput, error)
	IssueCertificateWithContext(aws.Context, *acmpca.IssueCertificateInput, ...request.Option) (*acmpca.IssueCertificateOutput, error)
	WaitUntilCertificateIssuedWithContext(aws.Context, *acmpca.GetCertificateInput, ...request.WaiterOption) error
	GetCertificateWithContext(aws.Context, *acmpca.GetCertificateInput, ...request.Option) (*acmpca.GetCertificateOutput, error)
}

func newPCAClient(config *PCAPluginConfiguration) (PCAClient, error) {
	awsConfig := &aws.Config{
		Region:   aws.String(config.Region),
		Endpoint: aws.String(config.Endpoint),
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
			Duration: 15 * time.Minute,
		})
	}

	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	return acmpca.New(awsSession), nil
}
