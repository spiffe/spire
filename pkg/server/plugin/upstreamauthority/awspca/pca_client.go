package awspca

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// PCAClient provides an interface which can be mocked to test
// the functionality of the plugin.
type PCAClient interface {
	DescribeCertificateAuthority(context.Context, *acmpca.DescribeCertificateAuthorityInput, ...func(*acmpca.Options)) (*acmpca.DescribeCertificateAuthorityOutput, error)
	IssueCertificate(context.Context, *acmpca.IssueCertificateInput, ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error)
	GetCertificate(context.Context, *acmpca.GetCertificateInput, ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error)
}

func newPCAClient(ctx context.Context, cfg *Configuration) (PCAClient, error) {
	var endpointResolver aws.EndpointResolverWithOptions
	if cfg.Endpoint != "" {
		endpointResolver = aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == acmpca.ServiceID && region == cfg.Region {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           cfg.Endpoint,
					SigningRegion: region,
				}, nil
			}

			return aws.Endpoint{}, fmt.Errorf("unknown endpoint requested")
		})
	}

	var credsProvider aws.CredentialsProvider
	switch {
	case cfg.AssumeRoleARN != "":
		stsClient := sts.NewFromConfig(aws.Config{})
		credsProvider = stscreds.NewAssumeRoleProvider(stsClient, cfg.AssumeRoleARN)
	default:
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region), config.WithEndpointResolverWithOptions(endpointResolver))
		if err != nil {
			return nil, err
		}

		credsProvider = awsCfg.Credentials
	}

	return acmpca.NewFromConfig(aws.Config{
		Region:                      cfg.Region,
		EndpointResolverWithOptions: endpointResolver,
		Credentials:                 credsProvider,
	}), nil
}
