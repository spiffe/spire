package awspca

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/stretchr/testify/require"
)

type pcaClientFake struct {
	t testing.TB

	describeCertificateOutput *acmpca.DescribeCertificateAuthorityOutput
	expectedDescribeInput     *acmpca.DescribeCertificateAuthorityInput
	describeCertificateErr    error

	issueCertificateOutput *acmpca.IssueCertificateOutput
	expectedIssueInput     *acmpca.IssueCertificateInput
	issueCertifcateErr     error

	expectedGetCertificateInput *acmpca.GetCertificateInput
	getCertificateOutput        *acmpca.GetCertificateOutput
	getCertificateErr           error

	waitUntilCertificateIssuedErr error
}

func (f *pcaClientFake) DescribeCertificateAuthorityWithContext(ctx aws.Context, input *acmpca.DescribeCertificateAuthorityInput, option ...request.Option) (*acmpca.DescribeCertificateAuthorityOutput, error) {
	require.Equal(f.t, f.expectedDescribeInput, input)
	if f.describeCertificateErr != nil {
		return nil, f.describeCertificateErr
	}
	return f.describeCertificateOutput, nil
}

func (f *pcaClientFake) IssueCertificateWithContext(ctx aws.Context, input *acmpca.IssueCertificateInput, option ...request.Option) (*acmpca.IssueCertificateOutput, error) {
	require.Equal(f.t, f.expectedIssueInput, input)
	if f.issueCertifcateErr != nil {
		return nil, f.issueCertifcateErr
	}
	return f.issueCertificateOutput, nil
}

func (f *pcaClientFake) WaitUntilCertificateIssuedWithContext(ctx aws.Context, input *acmpca.GetCertificateInput, option ...request.WaiterOption) error {
	require.Equal(f.t, f.expectedGetCertificateInput, input)

	return f.waitUntilCertificateIssuedErr
}

func (f *pcaClientFake) GetCertificateWithContext(ctx aws.Context, input *acmpca.GetCertificateInput, option ...request.Option) (*acmpca.GetCertificateOutput, error) {
	require.Equal(f.t, f.expectedGetCertificateInput, input)
	if f.getCertificateErr != nil {
		return nil, f.getCertificateErr
	}
	return f.getCertificateOutput, nil
}
