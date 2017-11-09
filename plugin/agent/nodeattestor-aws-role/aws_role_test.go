package main

import (
	"testing"
	"errors"

	"github.com/stretchr/testify/assert"

	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	goodConfig = `{"trust_domain":"example.com"}`

	arn = "arn:aws:iam::000267347458:user/bob"
	spiffeId =  "spiffe://example.com/spire/agent/aws_iam_role/000267347458/user/bob"
)

func PluginGenerator(config string) (nodeattestor.NodeAttestor, *spi.ConfigureResponse, error) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	defaultConfig := DefaultConfig()
	defaultConfig.stsClient = &mock_STSAPI{
		throwError: false,
	}


	p := New(defaultConfig)
	r, err := p.Configure(pluginConfig)
	return p, r, err
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)
	_, r, err := PluginGenerator(goodConfig)
	assert.Nil(err)
	assert.Equal(&spi.ConfigureResponse{}, r)
}


func TestIamRole_FetchAttestationData_IamRolePresent(t *testing.T) {
	assert := assert.New(t)

	// Build expected response
	attestationData := &common.AttestedData{
		Type: "aws_iam_role",
		Data: []byte(arn),
	}
	expectedResp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: attestationData,
		SpiffeId:     spiffeId,
	}

	p, _, err := PluginGenerator(goodConfig)
	assert.Nil(err)

	resp, err := p.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.Nil(err)
	assert.Equal(expectedResp, resp)
}

func TestIamRole_FetchAttestationData_IamRoleNotPresent(t *testing.T) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: goodConfig,
	}

	defaultConfig := DefaultConfig()
	defaultConfig.stsClient = &mock_STSAPI{
		throwError: true,
	}


	p := New(defaultConfig)
	_, err := p.Configure(pluginConfig)

	_, err = p.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	assert.NotNil(t, err)
}

type mock_STSAPI struct {
	throwError bool
}

func (mock_STSAPI) AssumeRole(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleWithContext(aws.Context, *sts.AssumeRoleInput, ...request.Option) (*sts.AssumeRoleOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleRequest(*sts.AssumeRoleInput) (*request.Request, *sts.AssumeRoleOutput) { return nil, nil }

func (mock_STSAPI) AssumeRoleWithSAML(*sts.AssumeRoleWithSAMLInput) (*sts.AssumeRoleWithSAMLOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleWithSAMLWithContext(aws.Context, *sts.AssumeRoleWithSAMLInput, ...request.Option) (*sts.AssumeRoleWithSAMLOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleWithSAMLRequest(*sts.AssumeRoleWithSAMLInput) (*request.Request, *sts.AssumeRoleWithSAMLOutput) { return nil, nil }

func (mock_STSAPI) AssumeRoleWithWebIdentity(*sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleWithWebIdentityWithContext(aws.Context, *sts.AssumeRoleWithWebIdentityInput, ...request.Option) (*sts.AssumeRoleWithWebIdentityOutput, error) { return nil, nil }
func (mock_STSAPI) AssumeRoleWithWebIdentityRequest(*sts.AssumeRoleWithWebIdentityInput) (*request.Request, *sts.AssumeRoleWithWebIdentityOutput) { return nil, nil }

func (mock_STSAPI) DecodeAuthorizationMessage(*sts.DecodeAuthorizationMessageInput) (*sts.DecodeAuthorizationMessageOutput, error) { return nil, nil }
func (mock_STSAPI) DecodeAuthorizationMessageWithContext(aws.Context, *sts.DecodeAuthorizationMessageInput, ...request.Option) (*sts.DecodeAuthorizationMessageOutput, error) { return nil, nil }
func (mock_STSAPI) DecodeAuthorizationMessageRequest(*sts.DecodeAuthorizationMessageInput) (*request.Request, *sts.DecodeAuthorizationMessageOutput) { return nil, nil }

func (m *mock_STSAPI) GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	if m.throwError == true {
		return nil, errors.New("Error during GetCallerIdentity")
	} else {
		id := sts.GetCallerIdentityOutput{}
		account := "000267347458"
		id.Account = &account

		arn := "arn:aws:iam::000267347458:user/bob"
		id.Arn = &arn

		user_id := "AKJAHSDKJHFE12653"
		id.UserId = &user_id
		return &id, nil
	}


}
func (mock_STSAPI) GetCallerIdentityWithContext(aws.Context, *sts.GetCallerIdentityInput, ...request.Option) (*sts.GetCallerIdentityOutput, error) { return nil, nil }
func (mock_STSAPI) GetCallerIdentityRequest(*sts.GetCallerIdentityInput) (*request.Request, *sts.GetCallerIdentityOutput) { return nil, nil }

func (mock_STSAPI) GetFederationToken(*sts.GetFederationTokenInput) (*sts.GetFederationTokenOutput, error) { return nil, nil }
func (mock_STSAPI) GetFederationTokenWithContext(aws.Context, *sts.GetFederationTokenInput, ...request.Option) (*sts.GetFederationTokenOutput, error) { return nil, nil }
func (mock_STSAPI) GetFederationTokenRequest(*sts.GetFederationTokenInput) (*request.Request, *sts.GetFederationTokenOutput) { return nil, nil }

func (mock_STSAPI) GetSessionToken(*sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error) { return nil, nil }
func (mock_STSAPI) GetSessionTokenWithContext(aws.Context, *sts.GetSessionTokenInput, ...request.Option) (*sts.GetSessionTokenOutput, error) { return nil, nil }
func (mock_STSAPI) GetSessionTokenRequest(*sts.GetSessionTokenInput) (*request.Request, *sts.GetSessionTokenOutput) { return nil, nil }
