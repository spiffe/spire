package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/agent/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"
)

func TestConfigure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	envs := map[string]string{
		"AWS_ACCESS_KEY_ID":     "foh",
		"AWS_SECRET_ACCESS_KEY": "bar",
	}

	p := &SecretsManagerPlugin{}
	p.hooks.getenv = func(key string) string {
		env := envs[key]
		return env
	}

	// Success access key and secret from config
	resp, err := p.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: `
access_key_id = "ACCESS_KEY"
secret_access_key = "ID"
regions = [ "r1", "r2", "r3" ]
		`,
	})

	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, &plugin.ConfigureResponse{}, resp)
	assert.Equal(t, "ACCESS_KEY", p.config.AccessKeyID)
	assert.Equal(t, "ID", p.config.SecretAccessKey)
	require.ElementsMatch(t, []string{"r1", "r2", "r3"}, p.config.Regions)

	// Success access key and secret from env vars
	resp, err = p.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: `
regions = [ "r4" ]
		`,
	})

	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, &plugin.ConfigureResponse{}, resp)
	assert.Equal(t, "foh", p.config.AccessKeyID)
	assert.Equal(t, "bar", p.config.SecretAccessKey)
	require.ElementsMatch(t, []string{"r4"}, p.config.Regions)

	// Malformed
	resp, err = p.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: "{ no a config }",
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "unable to decode configuration: 1:4: illegal char")
	require.Nil(t, resp)
}

func TestGetPluginInfo(t *testing.T) {
	p := &SecretsManagerPlugin{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	resp, err := p.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, &plugin.GetPluginInfoResponse{}, resp)
}

func TestPutX509SVID(t *testing.T) {
	successReq := &svidstore.PutX509SVIDRequest{
		Svid: &svidstore.X509SVID{
			SpiffeId:   "spiffe://example.org/lambda",
			CertChain:  []byte{1},
			PrivateKey: []byte{2},
			Bundle:     []byte{3},
			ExpiresAt:  123456,
		},
		Selectors: []*common.Selector{
			{Type: "aws_secretsmanager", Value: "secretname:secret1"},
		},
		FederatedBundles: map[string][]byte{
			"federated1": {4},
		},
	}

	for _, tt := range []struct {
		name      string
		req       *svidstore.PutX509SVIDRequest
		errCode   codes.Code
		errMsg    string
		smConfig  *smConfig
		noRegions bool
	}{
		{
			name: "Put SVID on existing secret",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/lambda",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "arn:secret1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			smConfig: &smConfig{
				drescribeInput: &secretsmanager.DescribeSecretInput{
					SecretId: aws.String("secret1"),
				},
				putSecretInput: &secretsmanager.PutSecretValueInput{
					SecretId: aws.String("secret1-arn"),
				},
				// Create must not be called
				createSecretErr: errors.New("unexpected error"),
				svid: &workload.X509SVIDResponse{
					Svids: []*workload.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/lambda",
							X509Svid:    []byte{1},
							X509SvidKey: []byte{2},
							Bundle:      []byte{3},
						},
					},
					FederatedBundles: map[string][]byte{
						"federated1": {4},
					},
				},
			},
		},
		{
			name: "Create secret and put SVID",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/lambda",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "secretname:secret1"},
					{Type: "aws_secretsmanager", Value: "kmskeyid:some-id"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			smConfig: &smConfig{
				createSecretInput: &secretsmanager.CreateSecretInput{
					Name:     aws.String("secret1"),
					KmsKeyId: aws.String("some-id"),
					Tags: []*secretsmanager.Tag{
						{Key: aws.String("spire-svid"), Value: aws.String("true")},
					},
				},
				describeErr:  awserr.New(secretsmanager.ErrCodeResourceNotFoundException, "failed to describe", errors.New("secret not found")),
				putSecretErr: errors.New("unexpected call to put secret"),
				svid: &workload.X509SVIDResponse{
					Svids: []*workload.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/lambda",
							X509Svid:    []byte{1},
							X509SvidKey: []byte{2},
							Bundle:      []byte{3},
						},
					},
					FederatedBundles: map[string][]byte{
						"federated1": {4},
					},
				},
			},
		},
		{
			name: "No secret name or arn",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/lambda",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "region:r5"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			errCode:  codes.InvalidArgument,
			errMsg:   "secret name or ARN are required",
			smConfig: &smConfig{},
		},
		{
			name: "failed to because no SVID provided",
			req: &svidstore.PutX509SVIDRequest{
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "secretname:secret1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			smConfig: &smConfig{},
			errCode:  codes.InvalidArgument,
			errMsg:   "failed to create SVID response: request does not contains a SVID",
		},
		{
			name:      "no regions",
			req:       successReq,
			noRegions: true,
			errCode:   codes.InvalidArgument,
			errMsg:    "at least one region is required",
			smConfig:  &smConfig{},
		},
		{
			name:    "failed to create secrets manager client",
			req:     successReq,
			errCode: codes.Internal,
			errMsg:  "failed to create secrets manager client: InternalServiceError: failed to create client\ncaused by: some error",
			smConfig: &smConfig{
				newClientErr: awserr.New(secretsmanager.ErrCodeInternalServiceError, "failed to create client", errors.New("some error")),
			},
		},
		{
			name:    "unnexpected aws error when describe secret",
			req:     successReq,
			errCode: codes.Internal,
			errMsg:  "failed to describe secret: InvalidParameterException: failed to describe secret\ncaused by: some error",
			smConfig: &smConfig{
				describeErr: awserr.New(secretsmanager.ErrCodeInvalidParameterException, "failed to describe secret", errors.New("some error")),
			},
		},
		{
			name:    "unnexpected regular error when describe secret",
			req:     successReq,
			errCode: codes.Internal,
			errMsg:  "failed to describe secret: some error",
			smConfig: &smConfig{
				describeErr: errors.New("some error"),
			},
		},
		{
			name:    "secrets does not contains spire-svid tag",
			req:     successReq,
			errCode: codes.InvalidArgument,
			errMsg:  "secret does not contain the 'spire-svid' tag",
			smConfig: &smConfig{
				drescribeInput: &secretsmanager.DescribeSecretInput{
					SecretId: aws.String("secret1"),
				},
				noTag: true,
			},
		},
		{
			name: "Fails to create secret",
			req:  successReq,
			smConfig: &smConfig{
				describeErr:     awserr.New(secretsmanager.ErrCodeResourceNotFoundException, "failed to describe", errors.New("secret not found")),
				createSecretErr: awserr.New(secretsmanager.ErrCodeInvalidRequestException, "failed to create secert", errors.New("some error")),
				putSecretErr:    errors.New("unexpected call to put secret"),
			},
			errCode: codes.Internal,
			errMsg:  "failed to create secret: InvalidRequestException: failed to create secert\ncaused by: some error",
		},
		{
			name: "Secret name is required to create secrets",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/lambda",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "arn:secret1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			smConfig: &smConfig{
				describeErr:  awserr.New(secretsmanager.ErrCodeResourceNotFoundException, "failed to describe", errors.New("secret not found")),
				putSecretErr: errors.New("unexpected call to put secret"),
			},
			errCode: codes.InvalidArgument,
			errMsg:  "failed to create secret: name selector is required",
		},
		{
			name: "Fails to put secret value",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/lambda",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "aws_secretsmanager", Value: "arn:secret1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			smConfig: &smConfig{
				drescribeInput: &secretsmanager.DescribeSecretInput{
					SecretId: aws.String("secret1"),
				},
				putSecretInput: &secretsmanager.PutSecretValueInput{
					SecretId: aws.String("secret1-arn"),
				},
				putSecretErr: awserr.New(secretsmanager.ErrCodeInternalServiceError, "failed to put secret value", errors.New("some error")),
				// Create must not be called
				createSecretErr: errors.New("unexpected error"),
			},
			errCode: codes.Internal,
			errMsg:  "failed to put secret value: InternalServiceError: failed to put secret value\ncaused by: some error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			regions := []string{}
			if !tt.noRegions {
				regions = append(regions, "r1")
			}

			pt := createPluginTest(t, tt.smConfig, regions)

			resp, err := pt.p.PutX509SVID(ctx, tt.req)

			if tt.errMsg != "" {
				spiretest.RequireGRPCStatus(t, err, tt.errCode, tt.errMsg)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, &svidstore.PutX509SVIDResponse{}, resp)
		})
	}
}

type pluginTest struct {
	sm *fakeSecretsManagerClient
	p  *SecretsManagerPlugin
}

func createPluginTest(t *testing.T, c *smConfig, regions []string) *pluginTest {
	sm := &fakeSecretsManagerClient{
		t: t,
		c: c,
	}

	p := newPlugin(sm.createTestClient)
	p.config = &Config{Regions: regions}
	p.SetLogger(hclog.NewNullLogger())

	return &pluginTest{
		sm: sm,
		p:  p,
	}
}

type smConfig struct {
	drescribeInput    *secretsmanager.DescribeSecretInput
	createSecretInput *secretsmanager.CreateSecretInput
	putSecretInput    *secretsmanager.PutSecretValueInput
	svid              *workload.X509SVIDResponse
	noTag             bool

	createSecretErr error
	describeErr     error
	newClientErr    error
	putSecretErr    error
}

type fakeSecretsManagerClient struct {
	t testing.TB

	c *smConfig
}

func (sm *fakeSecretsManagerClient) createTestClient(_, _, region string) (SecretsManagerClient, error) {
	if sm.c.newClientErr != nil {
		return nil, sm.c.newClientErr
	}
	if region == "" {
		return nil, errors.New("no region provided")
	}
	return sm, nil
}

func (sm *fakeSecretsManagerClient) DescribeSecret(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error) {
	if sm.c.describeErr != nil {
		return nil, sm.c.describeErr
	}
	resp := &secretsmanager.DescribeSecretOutput{
		ARN: aws.String(fmt.Sprintf("%s-arn", *input.SecretId)),
	}
	if !sm.c.noTag {
		resp.Tags = []*secretsmanager.Tag{
			{Key: aws.String("spire-svid"), Value: aws.String("true")},
		}
	}

	require.Equal(sm.t, sm.c.drescribeInput, input)
	return resp, nil
}

func (sm *fakeSecretsManagerClient) CreateSecret(input *secretsmanager.CreateSecretInput) (*secretsmanager.CreateSecretOutput, error) {
	if sm.c.createSecretErr != nil {
		return nil, sm.c.createSecretErr
	}

	b, err := proto.Marshal(sm.c.svid)
	require.NoError(sm.t, err)
	sm.c.createSecretInput.SecretBinary = b

	require.Equal(sm.t, sm.c.createSecretInput, input)
	return &secretsmanager.CreateSecretOutput{ARN: input.Name}, nil
}

func (sm *fakeSecretsManagerClient) PutSecretValue(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error) {
	if sm.c.putSecretErr != nil {
		return nil, sm.c.putSecretErr
	}

	b, err := proto.Marshal(sm.c.svid)
	require.NoError(sm.t, err)

	sm.c.putSecretInput.SecretBinary = b
	require.Equal(sm.t, sm.c.putSecretInput, input)

	return &secretsmanager.PutSecretValueOutput{ARN: input.SecretId, VersionId: aws.String("1")}, nil
}
