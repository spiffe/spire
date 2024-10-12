package gcpsecretmanager

import (
	"context"
	"crypto/sha1" //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	tdSum       = sha1.Sum([]byte("example.org")) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions
	tdHash      = hex.EncodeToString(tdSum[:])
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		trustDomain     spiffeid.TrustDomain
		customConfig    string
		newClientErr    error
		expectCode      codes.Code
		expectMsgPrefix string
		expectFilePath  string
		expectConfig    *Configuration
		expectTD        string
	}{
		{
			name:           "success",
			trustDomain:    trustDomain,
			expectFilePath: "someFile",
			expectConfig:   &Configuration{ServiceAccountFile: "someFile"},
			expectTD:       tdHash,
		},
		{
			name:         "no config file",
			trustDomain:  trustDomain,
			expectConfig: &Configuration{ServiceAccountFile: ""},
			expectTD:     tdHash,
		},
		{
			name:            "malformed configuration",
			trustDomain:     trustDomain,
			customConfig:    "{no a config}",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
		},
		{
			name:            "failed to create client",
			trustDomain:     trustDomain,
			expectConfig:    &Configuration{ServiceAccountFile: "someFile"},
			newClientErr:    errors.New("oh! no"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "failed to create secretmanager client: oh! no",
		},
		{
			name:        "contains unused keys",
			trustDomain: trustDomain,
			customConfig: `
service_account_file = "some_file"
invalid1 = "something"
invalid2 = "another"
`,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unknown configurations detected: invalid1,invalid2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: tt.trustDomain,
				}),
			}

			if tt.customConfig != "" {
				options = append(options, plugintest.Configure(tt.customConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Configuration{
					ServiceAccountFile: tt.expectFilePath,
				}))
			}

			newClient := func(ctx context.Context, serviceAccountFile string) (secretManagerClient, error) {
				assert.Equal(t, tt.expectFilePath, serviceAccountFile)
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}

				return &fakeClient{}, nil
			}

			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)

			// Expect no client unsuccess calls
			switch tt.expectCode {
			case codes.OK:
				require.Equal(t, tt.expectTD, p.tdHash)
				require.NotNil(t, p.secretManagerClient)
			default:
				require.Nil(t, p.secretManagerClient)
			}
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
			"name:secret1",
			"projectid:project1",
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

		expectSetIamPolicyReq     *iampb.SetIamPolicyRequest
		expectGetIamPolicyReq     *iampb.GetIamPolicyRequest
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
			name: "Update policy on existing secret: no bindings",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectGetIamPolicyReq: &iampb.GetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
			},
			expectSetIamPolicyReq: &iampb.SetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
				Policy: &iampb.Policy{
					Version: 0,
					Bindings: []*iampb.Binding{
						{
							Role:    "roles/secretmanager.viewer",
							Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
						},
					},
				},
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
			name: "Update policy on existing secret: different role",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectGetIamPolicyReq: &iampb.GetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
			},
			expectSetIamPolicyReq: &iampb.SetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
				Policy: &iampb.Policy{
					Version: 0,
					Bindings: []*iampb.Binding{
						{
							Role:    "roles/secretmanager.viewer",
							Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
						},
					},
				},
			},
			expectAddSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
				Parent: "projects/project1/secrets/secret1",
				Payload: &secretmanagerpb.SecretPayload{
					Data: payload,
				},
			},
			clientConfig: &clientConfig{
				binding: &iampb.Binding{
					Role:    "roles/custom",
					Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
				},
			},
		},
		{
			name: "Update policy on existing secret: different member",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectGetIamPolicyReq: &iampb.GetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
			},
			expectSetIamPolicyReq: &iampb.SetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
				Policy: &iampb.Policy{
					Version: 0,
					Bindings: []*iampb.Binding{
						{
							Role:    "roles/secretmanager.viewer",
							Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
						},
					},
				},
			},
			expectAddSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
				Parent: "projects/project1/secrets/secret1",
				Payload: &secretmanagerpb.SecretPayload{
					Data: payload,
				},
			},
			clientConfig: &clientConfig{
				binding: &iampb.Binding{
					Role:    "roles/secretmanager.viewer",
					Members: []string{"serviceAccount:another@test-proj.iam.gserviceaccount.com"},
				},
			},
		},
		{
			name: "No SetIamPolicy required",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectGetIamPolicyReq: &iampb.GetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
			},
			expectAddSecretVersionReq: &secretmanagerpb.AddSecretVersionRequest{
				Parent: "projects/project1/secrets/secret1",
				Payload: &secretmanagerpb.SecretPayload{
					Data: payload,
				},
			},
			clientConfig: &clientConfig{
				binding: &iampb.Binding{
					Role:    "roles/secretmanager.viewer",
					Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
				},
			},
		},
		{
			name: "Failed to get IAM policy",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			clientConfig: &clientConfig{
				binding: &iampb.Binding{
					Role:    "roles/secretmanager.viewer",
					Members: []string{"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com"},
				},
				getIamPolicyErr: status.Error(codes.Internal, "oh! no"),
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to get IAM policy: rpc error: code = Internal desc = oh! no",
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
						"spire-svid": tdHash,
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
			name: "Add IAM policy when creating",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
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
						"spire-svid": tdHash,
					},
				},
			},
			expectSetIamPolicyReq: &iampb.SetIamPolicyRequest{
				Resource: "projects/project1/secrets/secret1",
				Policy: &iampb.Policy{
					Version: 0,
					Bindings: []*iampb.Binding{
						{
							Role: "roles/secretmanager.viewer",
							Members: []string{
								"serviceAccount:test-secret@test-proj.iam.gserviceaccount.com",
							},
						},
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
			name: "SA is required when role is set",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): service account is required when role is set",
		},
		{
			name: "Role is required when SA is set",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): role is required when service account is set",
		},
		{
			name: "Failed to create IAM policy",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"projectid:project1",
					"role:roles/secretmanager.viewer",
					"serviceaccount:test-secret@test-proj.iam.gserviceaccount.com",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
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
						"spire-svid": tdHash,
					},
				},
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			clientConfig: &clientConfig{
				getSecretErr:    status.Error(codes.NotFound, "secret not found"),
				setIamPolicyErr: status.Error(codes.Internal, "oh! no"),
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to set IAM policy to secret: rpc error: code = Internal desc = oh! no",
		},
		{
			name: "invalid metadata",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"projectid"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): invalid metadata: metadata does not contain a colon: \"projectid\"",
		},
		{
			name: "invalid request, no secret name",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"projectid:project1"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): name is required",
		},
		{
			name: "invalid request, no secret project",
			req: &svidstore.X509SVID{
				SVID:             successReq.SVID,
				Metadata:         []string{"name:secret1"},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): projectid is required",
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
			expectMsgPrefix: "svidstore(gcp_secretmanager): secret is not managed by this SPIRE deployment",
		},
		{
			name: "Secret is in another trust domain",
			req:  successReq,
			clientConfig: &clientConfig{
				customLabelTD: "another.td",
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): secret is not managed by this SPIRE deployment",
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
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to create secret: rpc error: code = Internal desc = some error",
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
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to get secret: rpc error: code = Internal desc = some error",
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
					"name:secret1",
					"projectid:project1",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			clientConfig: &clientConfig{},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to parse request: failed to parse CertChain: x509: malformed certificate",
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
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to add secret version: rpc error: code = DeadlineExceeded desc = some error",
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
			p := newPlugin(client.newClient)

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: trustDomain,
				}),
				plugintest.ConfigureJSON(&Configuration{}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)
			require.NoError(t, err)

			// Call PutX509SVID
			err = ss.PutX509SVID(ctx, tt.req)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsgPrefix)

			// Validate what is sent to gcp
			spiretest.AssertProtoEqual(t, tt.expectAddSecretVersionReq, client.addSecretVersionReq)
			spiretest.AssertProtoEqual(t, tt.expectCreateSecretReq, client.createSecretReq)
			spiretest.AssertProtoEqual(t, tt.expectGetSecretReq, client.getSecretReq)
			spiretest.AssertProtoEqual(t, tt.expectSetIamPolicyReq, client.setIamPolicyReq)
			spiretest.AssertProtoEqual(t, tt.expectGetIamPolicyReq, client.getIamPolicyReq)
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
				"name:secret1",
				"projectid:project1",
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
				"name:secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): projectid is required",
		},
		{
			name: "no name provided",
			metadata: []string{
				"projectid:project1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): name is required",
		},
		{
			name: "Secret is not managed",
			metadata: []string{
				"name:secret1",
				"projectid:project1",
			},
			clientConfig: &clientConfig{
				noLabels: true,
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): secret is not managed by this SPIRE deployment",
		},
		{
			name: "Secret is in another TD",
			metadata: []string{
				"name:secret1",
				"projectid:project1",
			},
			clientConfig: &clientConfig{
				customLabelTD: "another.td",
			},
			expectGetSecretReq: &secretmanagerpb.GetSecretRequest{
				Name: "projects/project1/secrets/secret1",
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(gcp_secretmanager): secret is not managed by this SPIRE deployment",
		},
		{
			name: "Secret not found",
			metadata: []string{
				"name:secret1",
				"projectid:project1",
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
				"name:secret1",
				"projectid:project1",
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
			expectMsgPrefix: "svidstore(gcp_secretmanager): failed to delete secret: oh! no",
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
			p := newPlugin(client.newClient)

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Configuration{}),
			}
			require.NoError(t, err)

			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			// Delete SVID
			err = ss.DeleteX509SVID(ctx, tt.metadata)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsgPrefix)

			// Validate what is sent to gcp
			spiretest.AssertProtoEqual(t, tt.expectDeleteSecretReq, client.deleteSecretReq)
			spiretest.AssertProtoEqual(t, tt.expectGetSecretReq, client.getSecretReq)
		})
	}
}

type clientConfig struct {
	noLabels      bool
	customLabelTD string

	addSecretVersionErr error
	createSecretErr     error
	deleteSecretErr     error
	getSecretErr        error
	setIamPolicyErr     error
	getIamPolicyErr     error
	binding             *iampb.Binding
}

type fakeClient struct {
	t *testing.T

	addSecretVersionReq *secretmanagerpb.AddSecretVersionRequest
	createSecretReq     *secretmanagerpb.CreateSecretRequest
	deleteSecretReq     *secretmanagerpb.DeleteSecretRequest
	getSecretReq        *secretmanagerpb.GetSecretRequest
	setIamPolicyReq     *iampb.SetIamPolicyRequest
	getIamPolicyReq     *iampb.GetIamPolicyRequest
	c                   *clientConfig
}

func (c *fakeClient) newClient(context.Context, string) (secretManagerClient, error) {
	return c, nil
}

func (c *fakeClient) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if c.c.addSecretVersionErr != nil {
		return nil, c.c.addSecretVersionErr
	}

	c.addSecretVersionReq = req

	return &secretmanagerpb.SecretVersion{
		Name:  "v1",
		State: secretmanagerpb.SecretVersion_ENABLED,
	}, nil
}

func (c *fakeClient) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	if c.c.createSecretErr != nil {
		return nil, c.c.createSecretErr
	}

	c.createSecretReq = req

	return &secretmanagerpb.Secret{
		Name: fmt.Sprintf("projects/project1/secrets/%s", req.SecretId),
	}, nil
}

func (c *fakeClient) GetSecret(_ context.Context, req *secretmanagerpb.GetSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	c.getSecretReq = req

	if c.c.getSecretErr != nil {
		return nil, c.c.getSecretErr
	}

	resp := &secretmanagerpb.Secret{
		Name: req.Name,
	}
	if !c.c.noLabels {
		labelTD := tdHash
		if c.c.customLabelTD != "" {
			labelTD = c.c.customLabelTD
		}
		resp.Labels = map[string]string{"spire-svid": labelTD}
	}

	return resp, nil
}

func (c *fakeClient) DeleteSecret(_ context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	c.deleteSecretReq = req

	return c.c.deleteSecretErr
}

func (c *fakeClient) Close() error {
	return nil
}

func (c *fakeClient) GetIamPolicy(_ context.Context, req *iampb.GetIamPolicyRequest, _ ...gax.CallOption) (*iampb.Policy, error) {
	if c.c.getIamPolicyErr != nil {
		return nil, c.c.getIamPolicyErr
	}

	c.getIamPolicyReq = req

	bindings := []*iampb.Binding{}
	if c.c.binding != nil {
		bindings = append(bindings, c.c.binding)
	}

	return &iampb.Policy{
		Version:  0,
		Etag:     []byte{1},
		Bindings: bindings,
	}, nil
}

func (c *fakeClient) SetIamPolicy(_ context.Context, req *iampb.SetIamPolicyRequest, _ ...gax.CallOption) (*iampb.Policy, error) {
	if c.c.setIamPolicyErr != nil {
		return nil, c.c.setIamPolicyErr
	}

	c.setIamPolicyReq = req

	return &iampb.Policy{
		Version: 0,
		Etag:    []byte{1},
	}, nil
}
