package awspca

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/stretchr/testify/require"
)

type pcaClientFake struct {
	t *testing.T

	describeCertificateOutput *acmpca.DescribeCertificateAuthorityOutput
	expectedDescribeInput     *acmpca.DescribeCertificateAuthorityInput

	issueCertificateOutput *acmpca.IssueCertificateOutput
	expectedIssueInput     *acmpca.IssueCertificateInput

	expectedGetCertificateInput *acmpca.GetCertificateInput
	getCertificateOutput        *acmpca.GetCertificateOutput

	err error
}

func (f *pcaClientFake) DescribeCertificateAuthorityWithContext(ctx aws.Context, input *acmpca.DescribeCertificateAuthorityInput, option ...request.Option) (*acmpca.DescribeCertificateAuthorityOutput, error) {
	require.Equal(f.t, f.expectedDescribeInput, input)
	if f.err != nil {
		return nil, f.err
	}
	return f.describeCertificateOutput, nil
}

func (f *pcaClientFake) IssueCertificateWithContext(ctx aws.Context, input *acmpca.IssueCertificateInput, option ...request.Option) (*acmpca.IssueCertificateOutput, error) {
	require.Equal(f.t, f.expectedIssueInput, input)
	if f.err != nil {
		return nil, f.err
	}
	return f.issueCertificateOutput, nil
}

func (f *pcaClientFake) WaitUntilCertificateIssuedWithContext(ctx aws.Context, input *acmpca.GetCertificateInput, option ...request.WaiterOption) error {
	require.Equal(f.t, f.expectedGetCertificateInput, input)

	return f.err
}

func (f *pcaClientFake) GetCertificateWithContext(ctx aws.Context, input *acmpca.GetCertificateInput, option ...request.Option) (*acmpca.GetCertificateOutput, error) {
	require.Equal(f.t, f.expectedGetCertificateInput, input)
	if f.err != nil {
		return nil, f.err
	}
	return f.getCertificateOutput, nil
}

func (f *pcaClientFake) recycle(t *testing.T) {
	f.t = t

	f.describeCertificateOutput = nil
	f.expectedDescribeInput = nil

	f.issueCertificateOutput = nil
	f.expectedIssueInput = nil

	f.expectedGetCertificateInput = nil
	f.err = nil
	f.getCertificateOutput = nil
}
