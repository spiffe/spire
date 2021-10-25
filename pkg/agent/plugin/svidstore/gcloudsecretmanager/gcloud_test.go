package gcloudsecretmanager

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	x509CertPem = `-----BEGIN CERTIFICATE-----
MIICcDCCAdKgAwIBAgIBAjAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UEChMGU1BJRkZFMB4XDTE4MDIxMDAwMzY1NVoXDTE4MDIxMDAxMzY1NlowHTEL
MAkGA1UEBhMCVVMxDjAMBgNVBAoTBVNQSVJFMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQBfav2iunAwzozmwg5lq30ltm/X3XeBgxhbsWu4Rv+I5B22urvR0jxGQM7
TsquuQ/wpmJQgTgV9jnK/5fvl4GvhS8A+K2UXv6L3IlrHIcMG3VoQ+BeKo44Hwgu
keu5GMUKAiEF33acNWUHp7U+Swxdxw+CwR9bNnIf0ZTfxlqSBaJGVIujgb4wgbsw
DgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPhG423HoTvTKNXTAi9TKsaQwpzPMFsG
A1UdEQRUMFKGUHNwaWZmZTovL2V4YW1wbGUub3JnL3NwaXJlL2FnZW50L2pvaW5f
dG9rZW4vMmNmMzUzOGMtNGY5Yy00NmMwLWE1MjYtMWNhNjc5YTkyNDkyMAoGCCqG
SM49BAMEA4GLADCBhwJBLM2CaOSw8kzSBJUyAvg32PM1PhzsVEsGIzWS7b+hgKkJ
NlnJx6MZ82eamOCsCdTVrXUV5cxO8kt2yTmYxF+ucu0CQgGVmL65pzg2E4YfCES/
4th19FFMRiOTtNpI5j2/qLTptnanJ/rpqE0qsgA2AiSsnbnnW6B7Oa+oi7QDMOLw
l6+bdA==
-----END CERTIFICATE-----
`
	x509KeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`
	x509BundlePem = `-----BEGIN CERTIFICATE-----
MIICOTCCAZqgAwIBAgIBATAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UECgwGU1BJRkZFMB4XDTE4MDIxMDAwMzQ0NVoXDTE4MDIxMDAxMzQ1NVowHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTCBmzAQBgcqhkjOPQIBBgUrgQQA
IwOBhgAEAZ6nXrNctKHNjZT7ZkP7xwfpMfvc/DAHc39GdT3qi8mmowY0/XuFQmlJ
cXXwv8ZlOSoGvtuLAEx1lvHNZwv4BuuPALILcIW5tyC8pjcbfqs8PMQYwiC+oFKH
BTxXzolpLeHuFLAD9ccfwWhkT1z/t4pvLkP4FCkkBosG9PVg5JQVJuZJo4GFMIGC
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT4RuNt
x6E70yjV0wIvUyrGkMKczzAfBgNVHSMEGDAWgBRGyozl9Mjue0Y3w4c2Q+3u+wVk
CjAfBgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDBAOB
jAAwgYgCQgHOtx4sNCioAQnpEx3J/A9M6Lutth/ND/h8D+7luqEkd4tMrBQgnMj4
E0xLGUNtoFNRIrEUlgwksWvKZ3BksIIOMwJCAc8VPA/QYrlJDeQ58FKyQyrOIlPk
Q0qBJEOkL6FrAngY5218TCNUS30YS5HjI2lfyyjB+cSVFXX8Szu019dDBMhV
-----END CERTIFICATE-----
`
	x509FederatedBundlePem = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		customConfig    string
		expectCode      codes.Code
		expectMsgPrefix string
		filePath        string
		expectConfig    *Configuration
	}{
		{
			name:         "success",
			filePath:     "someFile",
			expectConfig: &Configuration{ServiceAccountFile: "someFile"},
		},
		{
			name:         "no config file",
			expectConfig: &Configuration{ServiceAccountFile: ""},
		},
		{
			name:            "malformed configuration",
			customConfig:    "{no a config}",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
			}

			if tt.customConfig != "" {
				options = append(options, plugintest.Configure(tt.customConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Configuration{
					ServiceAccountFile: tt.filePath,
				}))
			}

			p := new(SecretManagerPlugin)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			require.Equal(t, tt.expectConfig, p.config)
		})
	}
}

func TestPutX509SVID(t *testing.T) {
	x509Cert, err := pemutil.ParseCertificate([]byte(x509CertPem))
	require.NoError(t, err)

	x509Bundle, err := pemutil.ParseCertificate([]byte(x509BundlePem))
	require.NoError(t, err)

	federatedBundle, err := pemutil.ParseCertificate([]byte(x509FederatedBundlePem))
	require.NoError(t, err)

	x509Key, err := pemutil.ParseECPrivateKey([]byte(x509KeyPem))
	require.NoError(t, err)

	expiresAt := time.Now()
	successReq := &svidstore.X509SVID{
		SVID: &svidstore.SVID{
			SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/foh"),
			CertChain:  []*x509.Certificate{x509Cert},
			PrivateKey: x509Key,
			Bundle:     []*x509.Certificate{x509Bundle},
			ExpiresAt:  expiresAt,
		},
		Metadata: []string{
			"secretname:secret1",
			"secretproject:project1",
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"federated1": {federatedBundle},
		},
	}

	secret := &svidstore.Data{
		SPIFFEID:    "spiffe://example.org/foh",
		X509SVID:    x509CertPem,
		X509SVIDKey: x509KeyPem,
		Bundle:      x509BundlePem,
		FederatedBundles: map[string]string{
			"federated1": x509FederatedBundlePem,
		},
	}
	payload, err := json.Marshal(secret)
	assert.NoError(t, err)

	for _, tt := range []struct {
		name            string
		req             *svidstore.X509SVID
		expectCode      codes.Code
		expectMsgPrefix string

		clientConfig *clientConfig

		expectAddSecretVersionReq *secretmanagerpb.AddSecretVersionRequest
		expectCreateSecretReq     *secretmanagerpb.CreateSecretRequest
		expectGetSecretReq        *secretmanagerpb.GetSecretRequest
	}{
		{
			name: "Add payload to existing secret",
			req:  successReq,
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectAddSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
				Parent: "projects/project1/secrets/secret1",
				Payload: &secretmanagerpb.SecretPayload{
					Data: payload,
				},
			},
			clientConfig: &clientConfig{},
		},
		{
			name: "Add payload and create secret",
			req:  successReq,
			expectCreateSecretReq: &secretmanagerpb.CreateSecretRequest{
				Parent:   "projects/project1",
				SecretId: "secret1",
				Secret: &secretmanagerpb.Secret{
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
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectAddSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
				Parent: "projects/project1/secrets/secret1",
				Payload: &secretmanagerpb.SecretPayload{
					Data: payload,
				},
			},
			clientConfig: &clientConfig{
				getSecretErr: status.Error(codes.NotFound, "secret not found"),
			},
		},
		{
			name:            "Fail to create gcloud client",
			req:             successReq,
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to create secretmanager client: rpc error: code = Internal desc = oh! no",
			clientConfig: &clientConfig{
				newClientErr: status.Error(codes.Internal, "oh! no"),
			},
		},
		{
			name: "invalid metadata",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"secretproject"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): invalid metadata: metadata does not contains contain a colon: \"secretproject\"",
		},
		{
			name: "invalid request, no secret name",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"secretproject:project1"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secretname is required",
		},
		{
			name: "invalid request, no secret project",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"secretname:secret1"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secretproject is required",
		},
		{
			name: "Secret no spire-svid label",
			req:  successReq,
			clientConfig: &clientConfig{
				noLabels: true,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secret does not contain the 'spire-svid' label",
		},
		{
			name: "failed to create secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretErr:    status.Error(codes.NotFound, "secret not found"),
				createSecretErr: status.Error(codes.Internal, "some error"),
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to create secret: rpc error: code = Internal desc = some error",
		},
		{
			name: "failed to get secret",
			req:  successReq,
			clientConfig: &clientConfig{
				getSecretErr: status.Error(codes.Internal, "some error"),
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to get secret: rpc error: code = Internal desc = some error",
		},
		{
			name: "failed to parse request",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID: spiffeid.RequireFromString("spiffe://example.org/foh"),
					CertChain: []*x509.Certificate{
						{Raw: []byte("no a certificate")},
					},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{
					"secretname:secret1",
					"secretproject:project1",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			clientConfig: &clientConfig{},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to parse request: failed to parse CertChain: x509: malformed certificate",
		},
		{
			name: "Failed to add secret version",
			req:  successReq,
			clientConfig: &clientConfig{
				addSecretVersionErr: status.Error(codes.DeadlineExceeded, "some error"),
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to add secret version: rpc error: code = DeadlineExceeded desc = some error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			client := &fakeClient{
				t: t,
				c: tt.clientConfig,
			}

			// Prepare plungin
			p := new(SecretManagerPlugin)
			p.hooks.newClient = client.newClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Configuration{}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			// Call PutX509SVID
			err = ss.PutX509SVID(ctx, tt.req)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsgPrefix)

			// Validate what is sent to gcloud
			spiretest.AssertProtoEqual(t, tt.expectAddSecretVersionReq, client.addSecretVersionReq)
			spiretest.AssertProtoEqual(t, tt.expectCreateSecretReq, client.createSecretReq)
			spiretest.AssertProtoEqual(t, tt.expectGetSecretReq, client.getSecretReq)
		})
	}
}

func TestDeleteX509SVID(t *testing.T) {
	for _, tt := range []struct {
		name string

		metadata        []string
		expectCode      codes.Code
		expectMsgPrefix string

		clientConfig *clientConfig

		expectDeleteSecretReq *secretmanagerpb.DeleteSecretRequest
		expectGetSecretReq    *secretmanagerpb.GetSecretRequest
	}{
		{
			name: "delete successfully",
			metadata: []string{
				"secretname:secret1",
				"secretproject:project1",
			},
			clientConfig: &clientConfig{},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectDeleteSecretReq: &secretmanagerpb.DeleteSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
		},
		{
			name: "no project provided",
			metadata: []string{
				"secretname:secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secretproject is required",
		},
		{
			name: "no name provided",
			metadata: []string{
				"secretproject:project1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secretname is required",
		},
		{
			name: "failed to create client",
			metadata: []string{
				"secretname:secret1",
				"secretproject:project1",
			},
			clientConfig: &clientConfig{
				newClientErr: errors.New("oh! no"),
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to create secretmanager client: oh! no",
		},
		{
			name: "Secret is not managed",
			metadata: []string{
				"secretname:secret1",
				"secretproject:project1",
			},
			clientConfig: &clientConfig{
				noLabels: true,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): secret does not contain the 'spire-svid' label",
		},
		{
			name: "Secret not found",
			metadata: []string{
				"secretname:secret1",
				"secretproject:project1",
			},
			clientConfig: &clientConfig{
				getSecretErr: status.Error(codes.NotFound, "secret not found"),
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
		},
		{
			name: "DeleteSecret fails",
			metadata: []string{
				"secretname:secret1",
				"secretproject:project1",
			},
			clientConfig: &clientConfig{
				deleteSecretErr: errors.New("oh! no"),
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectDeleteSecretReq: &secretmanagerpb.DeleteSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcloud_secretmanager): failed to delete secret: oh! no",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			client := &fakeClient{
				t: t,
				c: tt.clientConfig,
			}

			// Prepare plugin
			p := new(SecretManagerPlugin)
			p.hooks.newClient = client.newClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Configuration{}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			// Delete SVID
			err = ss.DeleteX509SVID(ctx, tt.metadata)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsgPrefix)

			// Validate what is send to gcloud
			spiretest.AssertProtoEqual(t, tt.expectDeleteSecretReq, client.deleteSecretReq)
			spiretest.AssertProtoEqual(t, tt.expectGetSecretReq, client.getSecretReq)
		})
	}
}

type clientConfig struct {
	noLabels bool

	addSecretVersionErr error
	createSecretErr     error
	deleteSecretErr     error
	getSecretErr        error
	newClientErr        error
}

type fakeClient struct {
	t *testing.T

	addSecretVersionReq *secretmanagerpb.AddSecretVersionRequest
	createSecretReq     *secretmanagerpb.CreateSecretRequest
	deleteSecretReq     *secretmanagerpb.DeleteSecretRequest
	getSecretReq        *secretmanagerpb.GetSecretRequest
	c                   *clientConfig
}

func (c *fakeClient) newClient(ctx context.Context, serviceAccountFile string) (secretsClient, error) {
	if c.c.newClientErr != nil {
		return nil, c.c.newClientErr
	}

	return c, nil
}

func (c *fakeClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if c.c.addSecretVersionErr != nil {
		return nil, c.c.addSecretVersionErr
	}

	c.addSecretVersionReq = req

	return &secretmanagerpb.SecretVersion{
		Name:  "v1",
		State: secretmanagerpb.SecretVersion_ENABLED,
	}, nil
}

func (c *fakeClient) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	if c.c.createSecretErr != nil {
		return nil, c.c.createSecretErr
	}

	c.createSecretReq = req

	return &secretmanagerpb.Secret{
		Name: fmt.Sprintf("projects/project1/secrets/%s", req.SecretId),
	}, nil
}

func (c *fakeClient) GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	c.getSecretReq = req

	if c.c.getSecretErr != nil {
		return nil, c.c.getSecretErr
	}

	resp := &secretmanagerpb.Secret{
		Name: req.Name,
	}
	if !c.c.noLabels {
		resp.Labels = map[string]string{"spire-svid": "true"}
	}

	return resp, nil
}

func (c *fakeClient) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
	c.deleteSecretReq = req

	return c.c.deleteSecretErr
}

func (c *fakeClient) Close() error {
	return nil
}
