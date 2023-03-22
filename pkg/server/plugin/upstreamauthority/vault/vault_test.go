package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"text/template"
	"time"

	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
)

func TestConfigure(t *testing.T) {
	fakeVaultServer := setupFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
	fakeVaultServer.AppRoleAuthResponseCode = 200
	fakeVaultServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponse)
	fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	for _, tt := range []struct {
		name                     string
		configTmpl               string
		plainConfig              string
		expectMsgPrefix          string
		expectCode               codes.Code
		wantAuth                 AuthMethod
		wantNamespaceIsNotNil    bool
		envKeyVal                map[string]string
		expectToken              string
		expectCertAuthMountPoint string
		expectClientCertPath     string
		expectClientKeyPath      string
		appRoleAuthMountPoint    string
		appRoleID                string
		appRoleSecretID          string
		expectK8sAuthMountPoint  string
		expectK8sAuthRoleName    string
		expectK8sAuthTokenPath   string
	}{
		{
			name:        "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl:  testTokenAuthConfigTpl,
			wantAuth:    TOKEN,
			expectToken: "test-token",
		},
		{
			name:       "Configure plugin with Token authentication params given as environment variables",
			configTmpl: testTokenAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultToken: "test-token",
			},
			wantAuth:    TOKEN,
			expectToken: "test-token",
		},
		{
			name:                     "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl:               testCertAuthConfigTpl,
			wantAuth:                 CERT,
			expectCertAuthMountPoint: "test-cert-auth",
			expectClientCertPath:     "testdata/client-cert.pem",
			expectClientKeyPath:      "testdata/client-key.pem",
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given as environment variables",
			configTmpl: testCertAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultClientCert: "testdata/client-cert.pem",
				envVaultClientKey:  testClientKey,
			},
			wantAuth:                 CERT,
			expectCertAuthMountPoint: "test-cert-auth",
			expectClientCertPath:     testClientCert,
			expectClientKeyPath:      testClientKey,
		},
		{
			name:                  "Configure plugin with AppRole authenticate params given in config file",
			configTmpl:            testAppRoleAuthConfigTpl,
			wantAuth:              APPROLE,
			appRoleAuthMountPoint: "test-approle-auth",
			appRoleID:             "test-approle-id",
			appRoleSecretID:       "test-approle-secret-id",
		},
		{
			name:       "Configure plugin with AppRole authentication params given as environment variables",
			configTmpl: testAppRoleAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultAppRoleID:       "test-approle-id",
				envVaultAppRoleSecretID: "test-approle-secret-id",
			},
			wantAuth:              APPROLE,
			appRoleAuthMountPoint: "test-approle-auth",
			appRoleID:             "test-approle-id",
			appRoleSecretID:       "test-approle-secret-id",
		},
		{
			name:                    "Configure plugin with Kubernetes authentication params given in config file",
			configTmpl:              testK8sAuthConfigTpl,
			wantAuth:                K8S,
			expectK8sAuthMountPoint: "test-k8s-auth",
			expectK8sAuthTokenPath:  "testdata/k8s/token",
			expectK8sAuthRoleName:   "my-role",
		},
		{
			name:            "Multiple authentication methods configured",
			configTmpl:      testMultipleAuthConfigsTpl,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "only one authentication method can be configured",
		},
		{
			name:       "Pass VaultAddr via the environment variable",
			configTmpl: testConfigWithVaultAddrEnvTpl,
			envKeyVal: map[string]string{
				envVaultAddr: fmt.Sprintf("https://%v/", addr),
			},
			wantAuth:    TOKEN,
			expectToken: "test-token",
		},
		{
			name:                  "Configure plugin with given namespace",
			configTmpl:            testNamespaceConfigTpl,
			wantAuth:              TOKEN,
			wantNamespaceIsNotNil: true,
			expectToken:           "test-token",
		},
		{
			name:            "Malformed configuration",
			plainConfig:     "invalid-config",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
		},
		{
			name:            "Required parameters are not given / k8s_auth_role_name",
			configTmpl:      testK8sAuthNoRoleNameTpl,
			wantAuth:        K8S,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "k8s_auth_role_name is required",
		},
		{
			name:            "Required parameters are not given / token_path",
			configTmpl:      testK8sAuthNoTokenPathTpl,
			wantAuth:        K8S,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "token_path is required",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var err error

			p := New()
			p.hooks.lookupEnv = func(s string) (string, bool) {
				if len(tt.envKeyVal) == 0 {
					return "", false
				}
				v, ok := tt.envKeyVal[s]
				return v, ok
			}

			plainConfig := ""
			if tt.plainConfig != "" {
				plainConfig = tt.plainConfig
			} else {
				plainConfig = getTestConfigureRequest(t, fmt.Sprintf("https://%v/", addr), tt.configTmpl)
			}
			plugintest.Load(t, builtin(p), nil,
				plugintest.CaptureConfigureError(&err),
				plugintest.Configure(plainConfig),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("localhost"),
				}),
			)

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				return
			}

			require.NotNil(t, p.cc)
			require.NotNil(t, p.cc.clientParams)

			switch tt.wantAuth {
			case TOKEN:
				require.Equal(t, tt.expectToken, p.cc.clientParams.Token)
			case CERT:
				require.Equal(t, tt.expectCertAuthMountPoint, p.cc.clientParams.CertAuthMountPoint)
				require.Equal(t, tt.expectClientCertPath, p.cc.clientParams.ClientCertPath)
				require.Equal(t, tt.expectClientKeyPath, p.cc.clientParams.ClientKeyPath)
			case APPROLE:
				require.NotNil(t, p.cc.clientParams.AppRoleAuthMountPoint)
				require.NotNil(t, p.cc.clientParams.AppRoleID)
				require.NotNil(t, p.cc.clientParams.AppRoleSecretID)
			case K8S:
				require.Equal(t, tt.expectK8sAuthMountPoint, p.cc.clientParams.K8sAuthMountPoint)
				require.Equal(t, tt.expectK8sAuthRoleName, p.cc.clientParams.K8sAuthRoleName)
				require.Equal(t, tt.expectK8sAuthTokenPath, p.cc.clientParams.K8sAuthTokenPath)
			}

			if tt.wantNamespaceIsNotNil {
				require.NotNil(t, p.cc.clientParams.Namespace)
			}
		})
	}
}

func TestMintX509CA(t *testing.T) {
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)
	successfulConfig := &Configuration{
		PKIMountPoint: "test-pki",
		CACertPath:    "testdata/root-cert.pem",
		TokenAuth: &TokenAuthConfig{
			Token: "test-token",
		},
	}

	for _, tt := range []struct {
		name                    string
		csr                     []byte
		config                  *Configuration
		ttl                     time.Duration
		authMethod              AuthMethod
		expectCode              codes.Code
		expectMsgPrefix         string
		expectX509CA            []string
		expectedX509Authorities []string

		fakeServer func() *FakeVaultServerConfig
	}{
		{
			name: "Mint X509CA SVID with Token authentication",
			csr:  csr.Raw,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with custom ttl",
			csr:  csr.Raw,
			ttl:  time.Minute,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with Token authentication / Token is not renewable",
			csr:  csr.Raw,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponseNotRenewable)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with Token authentication / Token never expire",
			csr:  csr.Raw,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponseNeverExpire)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with TLS cert authentication",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     testClientCert,
					ClientKeyPath:      testClientKey,
				},
			},
			authMethod:              CERT,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.CertAuthResponse = []byte(testCertAuthResponse)
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with AppRole authentication",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod:              APPROLE,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponse)
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with Kubernetes authentication",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				K8sAuth: &K8sAuthConfig{
					K8sAuthMountPoint: "test-k8s-auth",
					K8sAuthRoleName:   "my-role",
					TokenPath:         "testdata/k8s/token",
				},
			},
			authMethod:              K8S,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.K8sAuthResponse = []byte(testK8sAuthResponse)
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with TLS cert authentication / Token is not renewable",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     testClientCert,
					ClientKeyPath:      testClientKey,
				},
			},
			authMethod:              CERT,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.CertAuthResponse = []byte(testCertAuthResponseNotRenewable)
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with AppRole authentication / Token is not renewable",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod:              APPROLE,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponseNotRenewable)
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with Kubernetes authentication / Token is not renewable",
			csr:  csr.Raw,
			config: &Configuration{
				CACertPath:    "testdata/root-cert.pem",
				PKIMountPoint: "test-pki",
				K8sAuth: &K8sAuthConfig{
					K8sAuthMountPoint: "test-k8s-auth",
					K8sAuthRoleName:   "my-role",
					TokenPath:         "testdata/k8s/token",
				},
			},
			authMethod:              K8S,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte{}
				fakeServer.K8sAuthResponse = []byte(testK8sAuthResponseNotRenewable)
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID with Namespace",
			csr:  csr.Raw,
			config: &Configuration{
				Namespace:     "test-ns",
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID against the RootCA Vault",
			csr:  csr.Raw,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testLegacySignIntermediateResponseNoChain)

				return fakeServer
			},
		},
		{
			name: "Mint X509CA SVID against the legacy Vault(~ v1.10.x)",
			csr:  csr.Raw,
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/root-cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.SignIntermediateResponse = []byte(testLegacySignIntermediateResponse)

				return fakeServer
			},
		},
		{
			name:                    "Plugin is not configured",
			csr:                     csr.Raw,
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-spire", "spiffe://intermediate-vault"},
			expectedX509Authorities: []string{"spiffe://root"},
			fakeServer:              setupSuccessFakeVaultServer,
			expectCode:              codes.FailedPrecondition,
			expectMsgPrefix:         "upstreamauthority(vault): plugin not configured",
		},
		{
			name:       "Authenticate client fails",
			csr:        csr.Raw,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				// Expect error
				fakeServer.LookupSelfResponse = []byte("fake-error")
				fakeServer.LookupSelfResponseCode = 500
				fakeServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(vault): failed to prepare authenticated client: rpc error: code = Internal desc = token lookup failed: Error making API request.",
		},
		{
			name:       "Signin fails",
			csr:        csr.Raw,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				// Expect error
				fakeServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
				fakeServer.SignIntermediateResponseCode = 500
				fakeServer.SignIntermediateResponse = []byte("fake-error")

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(vault): failed to sign intermediate: Error making API request.",
		},
		{
			name:       "Invalid signing response",
			csr:        csr.Raw,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				// Expect error
				fakeServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
				fakeServer.SignIntermediateResponseCode = 200
				fakeServer.SignIntermediateResponse = []byte(testInvalidSignIntermediateResponse)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(vault): failed to parse Root CA certificate:",
		},
		{
			name:       "Signing response malformed certificate",
			csr:        csr.Raw,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				// Expect error
				fakeServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
				fakeServer.SignIntermediateResponseCode = 200
				fakeServer.SignIntermediateResponse = []byte(testSignMalformedCertificateResponse)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(vault): failed to parse certificate: no PEM blocks",
		},
		{
			name:       "Signing response malformed certificate",
			csr:        csr.Raw,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer()
				// Expect error
				fakeServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
				fakeServer.SignIntermediateResponseCode = 200
				fakeServer.SignIntermediateResponse = []byte(testSignMalformedCertificateResponse)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(vault): failed to parse certificate: no PEM blocks",
		},
		{
			name:            "Invalid CSR",
			csr:             []byte("malformed-csr"),
			config:          successfulConfig,
			authMethod:      TOKEN,
			fakeServer:      setupSuccessFakeVaultServer,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "upstreamauthority(vault): failed to parse CSR data:",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer := tt.fakeServer()

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			p := New()
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			}
			if tt.config != nil {
				tt.config.VaultAddr = fmt.Sprintf("https://%s", addr)
				cp, err := p.genClientParams(tt.authMethod, tt.config)
				require.NoError(t, err)
				cc, err := NewClientConfig(cp, p.logger)
				require.NoError(t, err)
				p.cc = cc
				options = append(options, plugintest.ConfigureJSON(tt.config))
			}
			p.authMethod = tt.authMethod

			v1 := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), v1,
				options...,
			)

			x509CA, x509Authorities, stream, err := v1.MintX509CA(context.Background(), tt.csr, tt.ttl)

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				require.Nil(t, x509CA)
				require.Nil(t, x509Authorities)
				require.Nil(t, stream)
				return
			}
			require.NotNil(t, x509CA)
			require.NotNil(t, x509Authorities)
			require.NotNil(t, stream)

			x509CAIDs := certChainURIs(x509CA)
			require.Equal(t, tt.expectX509CA, x509CAIDs)

			x509AuthoritiesIDs := certChainURIs(x509Authorities)
			require.Equal(t, tt.expectedX509Authorities, x509AuthoritiesIDs)

			if p.cc.clientParams.Namespace != "" {
				headers := p.vc.vaultClient.Headers()
				require.Equal(t, p.cc.clientParams.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestMintX509CA_InvalidCSR(t *testing.T) {
	fakeVaultServer := setupFakeVaultServer()
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	fakeVaultServer.LookupSelfResponseCode = 200

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	p := New()

	v1 := new(upstreamauthority.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.ConfigureJSON(&Configuration{
			VaultAddr:     fmt.Sprintf("https://%v/", addr),
			CACertPath:    testRootCert,
			PKIMountPoint: "test-pki",
			TokenAuth: &TokenAuthConfig{
				Token: "test-token",
			},
		}),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
	)

	csr := []byte("invalid-csr")

	x509CA, x509Authorities, stream, err := v1.MintX509CA(context.Background(), csr, 3600)
	spiretest.AssertGRPCStatusHasPrefix(t, err, codes.InvalidArgument, "upstreamauthority(vault): failed to parse CSR data:")
	assert.Nil(t, x509CA)
	assert.Nil(t, x509Authorities)
	assert.Nil(t, stream)
}

func TestPublishJWTKey(t *testing.T) {
	fakeVaultServer := setupFakeVaultServer()
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	ua := new(upstreamauthority.V1)
	plugintest.Load(t, BuiltIn(), ua,
		plugintest.ConfigureJSON(Configuration{
			VaultAddr:     fmt.Sprintf("https://%v/", addr),
			CACertPath:    testRootCert,
			PKIMountPoint: "test-pki",
			TokenAuth: &TokenAuthConfig{
				Token: "test-token",
			},
		}),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	pkixBytes, err := x509.MarshalPKIXPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)

	jwtAuthorities, stream, err := ua.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(vault): publishing upstream is unsupported")
	assert.Nil(t, jwtAuthorities)
	assert.Nil(t, stream)
}

func getTestConfigureRequest(t *testing.T, addr string, tpl string) string {
	templ, err := template.New("plugin config").Parse(tpl)
	require.NoError(t, err)

	cp := &struct{ Addr string }{Addr: addr}

	var c bytes.Buffer
	err = templ.Execute(&c, cp)
	require.NoError(t, err)

	return c.String()
}

func setupFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
	fakeVaultServer.ServerCertificatePemPath = testServerCert
	fakeVaultServer.ServerKeyPemPath = testServerKey
	fakeVaultServer.RenewResponseCode = 200
	fakeVaultServer.RenewResponse = []byte(testRenewResponse)
	return fakeVaultServer
}

func setupSuccessFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := setupFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
	fakeVaultServer.AppRoleAuthResponseCode = 200
	fakeVaultServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponse)
	fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"
	fakeVaultServer.K8sAuthResponseCode = 200
	fakeVaultServer.K8sAuthReqEndpoint = "/v1/auth/test-k8s-auth/login"
	fakeVaultServer.K8sAuthResponse = []byte(testK8sAuthResponse)
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	fakeVaultServer.LookupSelfResponseCode = 200
	fakeVaultServer.SignIntermediateResponseCode = 200
	fakeVaultServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)
	fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"

	return fakeVaultServer
}

func certChainURIs(chain []*x509.Certificate) []string {
	var uris []string
	for _, cert := range chain {
		uris = append(uris, certURI(cert))
	}
	return uris
}

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}
