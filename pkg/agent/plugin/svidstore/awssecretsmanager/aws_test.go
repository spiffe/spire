package awssecretsmanager

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
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
	envs := map[string]string{
		"AWS_ACCESS_KEY_ID":     "foh",
		"AWS_SECRET_ACCESS_KEY": "bar",
	}

	for _, tt := range []struct {
		name            string
		envs            map[string]string
		accessKeyID     string
		secretAccessKey string
		region          string
		customConfig    string
		expectConfig    *Configuration
		expectCode      codes.Code
		expectMsgPrefix string
		expectClientErr error
	}{
		{
			name:            "access key and secret from config",
			envs:            envs,
			accessKeyID:     "ACCESS_KEY",
			secretAccessKey: "ID",
			region:          "r1",
			expectConfig: &Configuration{
				AccessKeyID:     "ACCESS_KEY",
				SecretAccessKey: "ID",
				Region:          "r1",
			},
		},
		{
			name:   "access key and secret from env vars",
			envs:   envs,
			region: "r1",
			expectConfig: &Configuration{
				AccessKeyID:     "foh",
				SecretAccessKey: "bar",
				Region:          "r1",
			},
		},
		{
			name:            "no region provided",
			envs:            envs,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "region is required",
		},
		{
			name:            "new client fails",
			envs:            envs,
			region:          "r1",
			expectClientErr: errors.New("oh no"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "failed to create secrets manager client: oh no",
		},
		{
			name:            "malformed configuration",
			envs:            envs,
			region:          "r1",
			customConfig:    "{ not a config }",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration: ",
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
					AccessKeyID:     tt.accessKeyID,
					SecretAccessKey: tt.secretAccessKey,
					Region:          tt.region,
				}))
			}

			p := new(SecretsManagerPlugin)
			p.hooks.getenv = func(key string) string {
				env := tt.envs[key]
				return env
			}

			newClientFunc := func(ctx context.Context, secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error) {
				if tt.expectClientErr != nil {
					return nil, tt.expectClientErr
				}
				if tt.expectConfig == nil {
					assert.Fail(t, "unexpected call to new client function")
					return nil, errors.New("unexpected call")
				}
				assert.Equal(t, tt.expectConfig.SecretAccessKey, secretAccessKey)
				assert.Equal(t, tt.expectConfig.AccessKeyID, accessKeyID)
				assert.Equal(t, tt.expectConfig.Region, region)
				return &fakeSecretsManagerClient{}, nil
			}
			p.hooks.newClient = newClientFunc

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			// Expect no client unsuccess calls
			switch tt.expectCode {
			case codes.OK:
				require.NotNil(t, p.smClient)
			default:
				require.Nil(t, p.smClient)
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
			SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
			CertChain:  []*x509.Certificate{x509Cert},
			PrivateKey: x509Key,
			Bundle:     []*x509.Certificate{x509Bundle},
			ExpiresAt:  expiresAt,
		},
		Metadata: []string{"secretname:secret1"},
		FederatedBundles: map[string][]*x509.Certificate{
			"federated1": {federatedBundle},
		},
	}

	for _, tt := range []struct {
		name       string
		req        *svidstore.X509SVID
		expectCode codes.Code
		expectMsg  string
		smConfig   *smConfig

		expectDescribeInput      *secretsmanager.DescribeSecretInput
		expectCreateSecretInput  func(*testing.T) *secretsmanager.CreateSecretInput
		expectPutSecretInput     func(*testing.T) *secretsmanager.PutSecretValueInput
		expectDeleteSecretInput  *secretsmanager.DeleteSecretInput
		expectRestoreSecretInput *secretsmanager.RestoreSecretInput
	}{
		{
			name: "Put SVID on existing secret",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{"arn:secret1"},
				FederatedBundles: map[string][]*x509.Certificate{
					"federated1": {federatedBundle},
				},
			},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectPutSecretInput: func(t *testing.T) *secretsmanager.PutSecretValueInput {
				secret := &svidstore.Data{
					SPIFFEID:    "spiffe://example.org/lambda",
					X509SVID:    x509CertPem,
					X509SVIDKey: x509KeyPem,
					Bundle:      x509BundlePem,
					FederatedBundles: map[string]string{
						"federated1": x509FederatedBundlePem,
					},
				}
				secretBinary, err := json.Marshal(secret)
				assert.NoError(t, err)

				return &secretsmanager.PutSecretValueInput{
					SecretId:     aws.String("secret1-arn"),
					SecretBinary: secretBinary,
				}
			},
			smConfig: &smConfig{},
		},
		{
			name: "Create secret and put SVID",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{
					"secretname:secret1",
					"kmskeyid:some-key-id",
				},
				FederatedBundles: map[string][]*x509.Certificate{
					"federated1": {federatedBundle},
				},
			},
			expectCreateSecretInput: func(t *testing.T) *secretsmanager.CreateSecretInput {
				expectSecret := &svidstore.Data{
					SPIFFEID:    "spiffe://example.org/lambda",
					X509SVID:    x509CertPem,
					X509SVIDKey: x509KeyPem,
					Bundle:      x509BundlePem,
					FederatedBundles: map[string]string{
						"federated1": x509FederatedBundlePem,
					},
				}
				secretBinary, err := json.Marshal(expectSecret)
				assert.NoError(t, err)

				return &secretsmanager.CreateSecretInput{
					Name:         aws.String("secret1"),
					SecretBinary: secretBinary,
					KmsKeyId:     aws.String("some-key-id"),
					Tags: []types.Tag{
						{Key: aws.String("spire-svid"), Value: aws.String("true")},
					},
				}
			},
			smConfig: &smConfig{
				describeErr: &types.ResourceNotFoundException{Message: aws.String("not found")},
			},
		},
		{
			name: "No secret name or arn",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{"kmskeyid:123"},
				FederatedBundles: map[string][]*x509.Certificate{
					"federated1": {federatedBundle},
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): either the secret name or ARN is required",
			smConfig:   &smConfig{},
		},
		{
			name: "failed to parse request",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
					CertChain:  []*x509.Certificate{{Raw: []byte("no a certificate")}},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{"secretname:secret1"},
				FederatedBundles: map[string][]*x509.Certificate{
					"federated1": {federatedBundle},
				},
			},
			smConfig:   &smConfig{},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): failed to parse request: failed to parse CertChain: x509: malformed certificate",
		},
		{
			name:       "unnexpected aws error when describe secret",
			req:        successReq,
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to describe secret: InvalidParameterException: failed to describe secret",
			smConfig: &smConfig{
				describeErr: &types.InvalidParameterException{Message: aws.String("failed to describe secret")},
			},
		},
		{
			name:       "unnexpected regular error when describe secret",
			req:        successReq,
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to describe secret: some error",
			smConfig: &smConfig{
				describeErr: errors.New("some error"),
			},
		},
		{
			name:       "secrets does not contain spire-svid tag",
			req:        successReq,
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): secret does not contain the 'spire-svid' tag",
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			smConfig: &smConfig{
				noTag: true,
			},
		},
		{
			name: "fails to create secret",
			req:  successReq,
			smConfig: &smConfig{
				describeErr:     &types.ResourceNotFoundException{Message: aws.String("not found")},
				createSecretErr: &types.InvalidRequestException{Message: aws.String("some error")},
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to create secret: InvalidRequestException: some error",
		},
		{
			name: "Secret name is required to create secrets",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/lambda"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  expiresAt,
				},
				Metadata: []string{"arn:secret1"},
				FederatedBundles: map[string][]*x509.Certificate{
					"federated1": {federatedBundle},
				},
			},
			smConfig: &smConfig{
				describeErr: &types.ResourceNotFoundException{Message: aws.String("not found")},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): failed to create secret: name selector is required",
		},
		{
			name: "Fails to put secret value",
			req:  successReq,
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectPutSecretInput: func(t *testing.T) *secretsmanager.PutSecretValueInput {
				secret := &svidstore.Data{
					SPIFFEID:    "spiffe://example.org/lambda",
					X509SVID:    x509CertPem,
					X509SVIDKey: x509KeyPem,
					Bundle:      x509BundlePem,
					FederatedBundles: map[string]string{
						"federated1": x509FederatedBundlePem,
					},
				}
				secretBinary, err := json.Marshal(secret)
				assert.NoError(t, err)

				return &secretsmanager.PutSecretValueInput{
					SecretId:     aws.String("secret1-arn"),
					SecretBinary: secretBinary,
				}
			},
			smConfig: &smConfig{
				putSecretErr: &types.InternalServiceError{Message: aws.String("failed to put secret value")},
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to put secret value: InternalServiceError: failed to put secret value",
		},
		{
			name: "Restore secret and update value",
			req:  successReq,
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectRestoreSecretInput: &secretsmanager.RestoreSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectPutSecretInput: func(t *testing.T) *secretsmanager.PutSecretValueInput {
				secret := &svidstore.Data{
					SPIFFEID:    "spiffe://example.org/lambda",
					X509SVID:    x509CertPem,
					X509SVIDKey: x509KeyPem,
					Bundle:      x509BundlePem,
					FederatedBundles: map[string]string{
						"federated1": x509FederatedBundlePem,
					},
				}
				secretBinary, err := json.Marshal(secret)
				assert.NoError(t, err)

				return &secretsmanager.PutSecretValueInput{
					SecretId:     aws.String("secret1-arn"),
					SecretBinary: secretBinary,
				}
			},
			smConfig: &smConfig{
				isDeleted: true,
			},
		},
		{
			name: "Restore secret fails",
			req:  successReq,
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectRestoreSecretInput: &secretsmanager.RestoreSecretInput{
				SecretId: aws.String("secret1"),
			},
			smConfig: &smConfig{
				isDeleted:        true,
				restoreSecretErr: &types.InvalidRequestException{Message: aws.String("some error")},
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to restore secret \"secret1\": InvalidRequestException: some error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			p := new(SecretsManagerPlugin)
			p.hooks.getenv = func(string) string {
				return ""
			}
			sm := &fakeSecretsManagerClient{
				t: t,
				c: tt.smConfig,
			}
			p.hooks.newClient = sm.createTestClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Configuration{Region: "r1"}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			err = ss.PutX509SVID(ctx, tt.req)

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}

			require.NoError(t, err)
			// Validate expected AWS api calls
			var createSecretInput *secretsmanager.CreateSecretInput
			if tt.expectCreateSecretInput != nil {
				createSecretInput = tt.expectCreateSecretInput(t)
			}
			require.Equal(t, createSecretInput, sm.createSecretInput)

			var putSecretInput *secretsmanager.PutSecretValueInput
			if tt.expectPutSecretInput != nil {
				putSecretInput = tt.expectPutSecretInput(t)
			}

			require.Equal(t, putSecretInput, sm.putSecretInput)

			require.Equal(t, tt.expectDeleteSecretInput, sm.deleteSecretInput)
			require.Equal(t, tt.expectDescribeInput, sm.drescribeSecretInput)
			require.Equal(t, tt.expectRestoreSecretInput, sm.restoreSecretInput)
		})
	}
}

func TestDeleteX509SVID(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		metadata                []string
		smConfig                *smConfig
		expectDeleteSecretInput *secretsmanager.DeleteSecretInput
		expectDescribeInput     *secretsmanager.DescribeSecretInput
		expectCode              codes.Code
		expectMsg               string
	}{
		{
			name:     "secret is deleted: name",
			metadata: []string{"secretname:secret1"},
			smConfig: &smConfig{},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectDeleteSecretInput: &secretsmanager.DeleteSecretInput{
				SecretId:             aws.String("secret1-arn"),
				RecoveryWindowInDays: aws.Int64(7),
			},
		},
		{
			name:     "secret is deleted: arn",
			metadata: []string{"arn:arn-secret1"},
			smConfig: &smConfig{},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("arn-secret1"),
			},
			expectDeleteSecretInput: &secretsmanager.DeleteSecretInput{
				SecretId:             aws.String("arn-secret1-arn"),
				RecoveryWindowInDays: aws.Int64(7),
			},
		},
		{
			name:       "secret name or arn are required",
			metadata:   []string{},
			smConfig:   &smConfig{},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): either the secret name or ARN is required",
		},
		{
			name:     "secret already deleted",
			metadata: []string{"secretname:secret1"},
			smConfig: &smConfig{
				describeErr: &types.ResourceNotFoundException{Message: aws.String("some error")},
			},
		},
		{
			name:     "fails to describe secret",
			metadata: []string{"secretname:secret1"},
			smConfig: &smConfig{
				describeErr: &types.InvalidRequestException{Message: aws.String("some error")},
			},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to describe secret: InvalidRequestException: some error",
		},
		{
			name:     "secret has no spire-svid tag",
			metadata: []string{"secretname:secret1"},
			smConfig: &smConfig{
				noTag: true,
			},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(aws_secretsmanager): secret does not contain the 'spire-svid' tag",
		},
		{
			name:     "fails to delete secret",
			metadata: []string{"secretname:secret1"},
			smConfig: &smConfig{
				deleteSecretErr: &types.InvalidRequestException{Message: aws.String("some error")},
			},
			expectDescribeInput: &secretsmanager.DescribeSecretInput{
				SecretId: aws.String("secret1"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(aws_secretsmanager): failed to delete secret \"secret1\": InvalidRequestException: some error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			p := new(SecretsManagerPlugin)
			p.hooks.getenv = func(string) string {
				return ""
			}
			sm := &fakeSecretsManagerClient{
				t: t,
				c: tt.smConfig,
			}
			p.hooks.newClient = sm.createTestClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Configuration{Region: "r1"}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			err = ss.DeleteX509SVID(ctx, tt.metadata)

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}

			require.NoError(t, err)

			require.Equal(t, tt.expectDeleteSecretInput, sm.deleteSecretInput)
			require.Equal(t, tt.expectDescribeInput, sm.drescribeSecretInput)
		})
	}
}

type smConfig struct {
	noTag     bool
	isDeleted bool

	createSecretErr  error
	describeErr      error
	newClientErr     error
	putSecretErr     error
	deleteSecretErr  error
	restoreSecretErr error
}

type fakeSecretsManagerClient struct {
	t testing.TB

	drescribeSecretInput *secretsmanager.DescribeSecretInput
	createSecretInput    *secretsmanager.CreateSecretInput
	putSecretInput       *secretsmanager.PutSecretValueInput
	deleteSecretInput    *secretsmanager.DeleteSecretInput
	restoreSecretInput   *secretsmanager.RestoreSecretInput
	c                    *smConfig
}

func (sm *fakeSecretsManagerClient) createTestClient(_ context.Context, _, _, region string) (SecretsManagerClient, error) {
	if sm.c.newClientErr != nil {
		return nil, sm.c.newClientErr
	}
	if region == "" {
		return nil, errors.New("no region provided")
	}
	return sm, nil
}

func (sm *fakeSecretsManagerClient) DescribeSecret(_ context.Context, input *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	if sm.c.describeErr != nil {
		return nil, sm.c.describeErr
	}
	resp := &secretsmanager.DescribeSecretOutput{
		ARN: aws.String(fmt.Sprintf("%s-arn", *input.SecretId)),
	}
	if !sm.c.noTag {
		resp.Tags = []types.Tag{
			{Key: aws.String("spire-svid"), Value: aws.String("true")},
		}
	}

	if sm.c.isDeleted {
		resp.DeletedDate = aws.Time(time.Now())
	}

	sm.drescribeSecretInput = input
	return resp, nil
}

func (sm *fakeSecretsManagerClient) CreateSecret(_ context.Context, input *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	if sm.c.createSecretErr != nil {
		return nil, sm.c.createSecretErr
	}

	sm.createSecretInput = input
	return &secretsmanager.CreateSecretOutput{ARN: input.Name}, nil
}

func (sm *fakeSecretsManagerClient) PutSecretValue(_ context.Context, input *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if sm.c.putSecretErr != nil {
		return nil, sm.c.putSecretErr
	}

	// secretBinary, err := json.Marshal(sm.c.expectSecret)
	// assert.NoError(sm.t, err)
	sm.putSecretInput = input

	return &secretsmanager.PutSecretValueOutput{ARN: input.SecretId, VersionId: aws.String("1")}, nil
}

func (sm *fakeSecretsManagerClient) DeleteSecret(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	if sm.c.deleteSecretErr != nil {
		return nil, sm.c.deleteSecretErr
	}

	sm.deleteSecretInput = params

	return &secretsmanager.DeleteSecretOutput{
		ARN:  aws.String(*params.SecretId + "-arn"),
		Name: params.SecretId,
	}, nil
}
func (sm *fakeSecretsManagerClient) RestoreSecret(_ context.Context, params *secretsmanager.RestoreSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.RestoreSecretOutput, error) {
	if sm.c.restoreSecretErr != nil {
		return nil, sm.c.restoreSecretErr
	}

	sm.restoreSecretInput = params
	return &secretsmanager.RestoreSecretOutput{
		ARN:  aws.String(*params.SecretId + "-arn"),
		Name: params.SecretId,
	}, nil
}
