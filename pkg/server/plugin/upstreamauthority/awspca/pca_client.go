package awspca

import (
	"context"

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
	var configOpts []func(*config.LoadOptions) error
	if cfg.Region != "" {
		configOpts = append(configOpts, config.WithRegion(cfg.Region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, configOpts...)
	if err != nil {
		return nil, err
	}

	if cfg.AssumeRoleARN != "" {
		awsCfg, err = newAWSAssumeRoleConfig(ctx, cfg.Region, awsCfg, cfg.AssumeRoleARN)
		if err != nil {
			return nil, err
		}
	}

	var acmpcaOpts []func(*acmpca.Options)
	if cfg.Endpoint != "" {
		acmpcaOpts = append(acmpcaOpts, func(o *acmpca.Options) { o.BaseEndpoint = aws.String(cfg.Endpoint) })
	}

	return acmpca.NewFromConfig(awsCfg, acmpcaOpts...), nil
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
