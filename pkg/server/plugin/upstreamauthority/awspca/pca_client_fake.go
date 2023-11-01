package awspca

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/stretchr/testify/require"
)

type pcaClientFake struct {
	t testing.TB

	describeCertificateOutput *acmpca.DescribeCertificateAuthorityOutput
	expectedDescribeInput     *acmpca.DescribeCertificateAuthorityInput
	describeCertificateErr    error

	issueCertificateOutput *acmpca.IssueCertificateOutput
	expectedIssueInput     *acmpca.IssueCertificateInput
	issueCertificateErr    error

	expectedGetCertificateInput *acmpca.GetCertificateInput
	getCertificateOutput        *acmpca.GetCertificateOutput
	getCertificateErr           error
}

func (f *pcaClientFake) DescribeCertificateAuthority(_ context.Context, input *acmpca.DescribeCertificateAuthorityInput, _ ...func(*acmpca.Options)) (*acmpca.DescribeCertificateAuthorityOutput, error) {
	require.Equal(f.t, f.expectedDescribeInput, input)
	if f.describeCertificateErr != nil {
		return nil, f.describeCertificateErr
	}
	return f.describeCertificateOutput, nil
}

func (f *pcaClientFake) IssueCertificate(_ context.Context, input *acmpca.IssueCertificateInput, _ ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error) {
	require.Equal(f.t, f.expectedIssueInput, input)
	if f.issueCertificateErr != nil {
		return nil, f.issueCertificateErr
	}
	return f.issueCertificateOutput, nil
}

func (f *pcaClientFake) GetCertificate(_ context.Context, input *acmpca.GetCertificateInput, _ ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error) {
	require.Equal(f.t, f.expectedGetCertificateInput, input)
	if f.getCertificateErr != nil {
		return nil, f.getCertificateErr
	}
	return f.getCertificateOutput, nil
}
