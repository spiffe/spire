package gcloud

import (
	"context"
	"fmt"
	"testing"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestConfigure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	p := New()

	// Success, with file
	resp, err := p.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: `
service_account_file = "someFile"
		`,
	})
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, &spi.ConfigureResponse{}, resp)
	require.Equal(t, &Config{ServiceAccountFile: "someFile"}, p.config)

	// Success, no config file
	resp, err = p.Configure(ctx, &plugin.ConfigureRequest{
		Configuration: "",
	})
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, &spi.ConfigureResponse{}, resp)
	require.Equal(t, &Config{ServiceAccountFile: ""}, p.config)

	// Malformed config
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
			SpiffeId:   "spiffe://example.org/foh",
			CertChain:  []byte{1},
			PrivateKey: []byte{2},
			Bundle:     []byte{3},
			ExpiresAt:  123456,
		},
		Selectors: []*common.Selector{
			{Type: "gcloud_secretsmanager", Value: "secretname:secret1"},
			{Type: "gcloud_secretsmanager", Value: "secretproject:project1"},
		},
		FederatedBundles: map[string][]byte{
			"federated1": {4},
		},
	}

	for _, tt := range []struct {
		name    string
		req     *svidstore.PutX509SVIDRequest
		errCode codes.Code
		errMsg  string

		createClientErr error
		clientConfig    *clientConfig
	}{
		{
			name: "Add payload to existing secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretReq: &secretmanagerpb.GetSecretRequest{
					Name: "projects/project1/secrets/secret1",
				},
				addSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
					Parent: "projects/project1/secrets/secret1",
				},
				svid: &workload.X509SVIDResponse{
					Svids: []*workload.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/foh",
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
			name: "Add payload and create secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretErr: status.Error(codes.NotFound, "secret not found"),
				createSecretReq: &secretmanagerpb.CreateSecretRequest{
					Parent:   "projects/project1",
					SecretId: "secret1",
					Secret: &secretmanagerpb.Secret{
						// TODO: what replication type must we use here?
						Replication: &secretmanagerpb.Replication{
							Replication: &secretmanagerpb.Replication_Automatic_{
								Automatic: &secretmanagerpb.Replication_Automatic{},
							},
						},
						Labels: map[string]string{
							"spire-svid": "true",
						},
					},
				},
				addSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
					Parent: "projects/project1/secrets/secret1",
				},
				svid: &workload.X509SVIDResponse{
					Svids: []*workload.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/foh",
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
			name:            "Fail to create gcloud client",
			req:             successReq,
			errCode:         codes.Internal,
			errMsg:          "failed to create secretmanager client: rpc error: code = Internal desc = some error",
			createClientErr: status.Error(codes.Internal, "some error"),
		},
		{
			name: "invalid request, no secret name",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/foh",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "gcloud_secretsmanager", Value: "secretproject:project1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			errCode: codes.InvalidArgument,
			errMsg:  "selector 'secretname' is required",
		},
		{
			name: "invalid request, no secret project",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/foh",
					CertChain:  []byte{1},
					PrivateKey: []byte{2},
					Bundle:     []byte{3},
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "gcloud_secretsmanager", Value: "secretname:secret1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			errCode: codes.InvalidArgument,
			errMsg:  "selector 'secretproject' is required",
		},
		{
			name: "Secret no spire-svid label",
			req:  successReq,
			clientConfig: &clientConfig{
				noLabels: true,
				getSecretReq: &secretmanagerpb.GetSecretRequest{
					Name: "projects/project1/secrets/secret1",
				},
			},
			errCode: codes.InvalidArgument,
			errMsg:  "secret that not contains 'spire-svid' label",
		},
		{
			name: "failed to create secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretErr:    status.Error(codes.NotFound, "secret not found"),
				createSecretErr: status.Error(codes.Internal, "some error"),
			},
			errCode: codes.Internal,
			errMsg:  "failed to create secret: rpc error: code = Internal desc = some error",
		},
		{
			name: "failed to get secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretErr: status.Error(codes.Internal, "some error"),
			},
			errCode: codes.Internal,
			errMsg:  "failed to get secret: rpc error: code = Internal desc = some error",
		},
		{
			name: "failed to encode secret",
			req: &svidstore.PutX509SVIDRequest{
				Selectors: []*common.Selector{
					{Type: "gcloud_secretsmanager", Value: "secretname:secret1"},
					{Type: "gcloud_secretsmanager", Value: "secretproject:project1"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {4},
				},
			},
			clientConfig: &clientConfig{
				getSecretReq: &secretmanagerpb.GetSecretRequest{
					Name: "projects/project1/secrets/secret1",
				},
			},
			errCode: codes.InvalidArgument,
			errMsg:  "failed to encode secret: request does not contains a SVID",
		},
		{
			name: "Failed to add secret version",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretReq: &secretmanagerpb.GetSecretRequest{
					Name: "projects/project1/secrets/secret1",
				},
				addSecretVersionErr: status.Error(codes.DeadlineExceeded, "some error"),
			},
			errCode: codes.Internal,
			errMsg:  "failed to add secret version: rpc error: code = DeadlineExceeded desc = some error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			pt := setupPluginTest(t)
			pt.c.c = tt.clientConfig
			pt.newClientErr = tt.createClientErr

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
	p *SecretsManagerPlugin
	c *fakeClient

	newClientErr error
}

func setupPluginTest(t *testing.T) *pluginTest {
	pt := &pluginTest{
		c: &fakeClient{t: t},
	}
	p := New()
	p.hooks.newClient = pt.newClient
	p.SetLogger(hclog.NewNullLogger())
	p.config = &Config{}
	pt.p = p

	return pt
}

func (p *pluginTest) newClient(context.Context, string) (secretsClient, error) {
	if p.newClientErr != nil {
		return nil, p.newClientErr
	}
	return p.c, nil
}

type clientConfig struct {
	addSecretVersionReq *secretmanagerpb.AddSecretVersionRequest
	createSecretReq     *secretmanagerpb.CreateSecretRequest
	getSecretReq        *secretmanagerpb.GetSecretRequest
	noLabels            bool
	svid                *workload.X509SVIDResponse

	addSecretVersionErr error
	createSecretErr     error
	getSecretErr        error
}

type fakeClient struct {
	t *testing.T

	c *clientConfig
}

func (c *fakeClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if c.c.addSecretVersionErr != nil {
		return nil, c.c.addSecretVersionErr
	}

	b, err := proto.Marshal(c.c.svid)
	require.NoError(c.t, err)
	c.c.addSecretVersionReq.Payload = &secretmanagerpb.SecretPayload{
		Data: b,
	}
	spiretest.RequireProtoEqual(c.t, c.c.addSecretVersionReq, req)

	return &secretmanagerpb.SecretVersion{
		Name:  "v1",
		State: secretmanagerpb.SecretVersion_ENABLED,
	}, nil
}

func (c *fakeClient) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	if c.c.createSecretErr != nil {
		return nil, c.c.createSecretErr
	}

	spiretest.RequireProtoEqual(c.t, c.c.createSecretReq, req)

	return &secretmanagerpb.Secret{
		Name: fmt.Sprintf("projects/project1/secrets/%s", req.SecretId),
	}, nil
}

func (c *fakeClient) GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	if c.c.getSecretErr != nil {
		return nil, c.c.getSecretErr
	}

	spiretest.RequireProtoEqual(c.t, c.c.getSecretReq, req)
	resp := &secretmanagerpb.Secret{
		Name: req.Name,
	}
	if !c.c.noLabels {
		resp.Labels = map[string]string{"spire-svid": "true"}
	}

	return resp, nil
}
