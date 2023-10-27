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
	var opts []func(*config.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}

	if cfg.Endpoint != "" {
		endpointResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...any) (aws.Endpoint, error) {
			if service == acmpca.ServiceID && region == cfg.Region {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           cfg.Endpoint,
					SigningRegion: region,
				}, nil
			}

			return aws.Endpoint{}, fmt.Errorf("unknown endpoint %s requested for region %s", service, region)
		})
		opts = append(opts, config.WithEndpointResolverWithOptions(endpointResolver))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	if cfg.AssumeRoleARN != "" {
		awsCfg, err = newAWSAssumeRoleConfig(ctx, cfg.Region, awsCfg, cfg.AssumeRoleARN)
		if err != nil {
			return nil, err
		}
	}

	return acmpca.NewFromConfig(awsCfg), nil
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
