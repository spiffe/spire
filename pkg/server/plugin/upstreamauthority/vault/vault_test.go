package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"text/template"

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
	fakeVaultServer := setupFakeVautServer()
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
		AppRoleAuthMountPoint    string
		AppRoleID                string
		AppRoleSecretID          string
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
			expectClientCertPath:     "testdata/keys/EC/client_cert.pem",
			expectClientKeyPath:      "testdata/keys/EC/client_key.pem",
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given as environment variables",
			configTmpl: testCertAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultClientCert: "testdata/keys/EC/client_cert.pem",
				envVaultClientKey:  "testdata/keys/EC/client_key.pem",
			},
			wantAuth:                 CERT,
			expectCertAuthMountPoint: "test-cert-auth",
			expectClientCertPath:     "testdata/keys/EC/client_cert.pem",
			expectClientKeyPath:      "testdata/keys/EC/client_key.pem",
		},
		{
			name:                  "Configure plugin with AppRole authenticate params given in config file",
			configTmpl:            testAppRoleAuthConfigTpl,
			wantAuth:              APPROLE,
			AppRoleAuthMountPoint: "test-approle-auth",
			AppRoleID:             "test-approle-id",
			AppRoleSecretID:       "test-approle-secret-id",
		},
		{
			name:       "Configure plugin with AppRole authentication params given as environment variables",
			configTmpl: testAppRoleAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultAppRoleID:       "test-approle-id",
				envVaultAppRoleSecretID: "test-approle-secret-id",
			},
			wantAuth:              APPROLE,
			AppRoleAuthMountPoint: "test-approle-auth",
			AppRoleID:             "test-approle-id",
			AppRoleSecretID:       "test-approle-secret-id",
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
			}

			if tt.wantNamespaceIsNotNil {
				require.NotNil(t, p.cc.clientParams.Namespace)
			}
		})
	}
}

func TestMintX509CA(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		lookupSelfResp          []byte
		certAuthResp            []byte
		appRoleAuthResp         []byte
		signIntermediateResp    []byte
		config                  *Configuration
		authMethod              AuthMethod
		reuseToken              bool
		expectCode              codes.Code
		expectMsgPrefix         string
		expectX509CA            []string
		expectedX509Authorities []string
	}{
		{
			name:                 "Mint X509CA SVID with Token authentication",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with Token authentication / Token is not renewable",
			lookupSelfResp:       []byte(testLookupSelfResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with Token authentication / Token never expire",
			lookupSelfResp:       []byte(testLookupSelfResponseNeverExpire),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with TLS cert authentication",
			certAuthResp:         []byte(testCertAuthResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     "testdata/keys/EC/client_cert.pem",
					ClientKeyPath:      "testdata/keys/EC/client_key.pem",
				},
			},
			authMethod:              CERT,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with AppRole authentication",
			appRoleAuthResp:      []byte(testAppRoleAuthResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod:              APPROLE,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with TLS cert authentication / Token is not renewable",
			certAuthResp:         []byte(testCertAuthResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     "testdata/keys/EC/client_cert.pem",
					ClientKeyPath:      "testdata/keys/EC/client_key.pem",
				},
			},
			authMethod:              CERT,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with AppRole authentication / Token is not renewable",
			appRoleAuthResp:      []byte(testAppRoleAuthResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod:              APPROLE,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID with Namespace",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &Configuration{
				Namespace:     "test-ns",
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate-vault", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			name:                 "Mint X509CA SVID against the RootCA Vault",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponseNoChain),
			config: &Configuration{
				PKIMountPoint: "test-pki",
				CACertPath:    "testdata/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod:              TOKEN,
			reuseToken:              true,
			expectX509CA:            []string{"spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer := setupFakeVautServer()
			fakeVaultServer.CertAuthResponseCode = 200
			fakeVaultServer.CertAuthResponse = tt.certAuthResp
			fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
			fakeVaultServer.AppRoleAuthResponseCode = 200
			fakeVaultServer.AppRoleAuthResponse = tt.appRoleAuthResp
			fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"
			fakeVaultServer.LookupSelfResponse = tt.lookupSelfResp
			fakeVaultServer.LookupSelfResponseCode = 200
			fakeVaultServer.SignIntermediateResponseCode = 200
			fakeVaultServer.SignIntermediateResponse = tt.signIntermediateResp
			fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			p := New()

			tt.config.VaultAddr = fmt.Sprintf("https://%s", addr)
			cp := p.genClientParams(tt.authMethod, tt.config)
			cc, err := NewClientConfig(cp, p.logger)
			require.NoError(t, err)
			p.cc = cc
			p.authMethod = tt.authMethod

			v1 := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), v1,
				plugintest.ConfigureJSON(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			)

			csr, err := pemutil.LoadCertificateRequest(testReqCSR)
			require.NoError(t, err)

			x509CA, x509Authorities, stream, err := v1.MintX509CA(context.Background(), csr.Raw, 3600)
			require.NoError(t, err)
			require.NotNil(t, x509CA)
			require.NotNil(t, x509Authorities)
			require.NotNil(t, stream)

			x509CAIDs := certChainURIs(x509CA)
			require.Equal(t, tt.expectX509CA, x509CAIDs)

			x509AuthoritiesIDs := certChainURIs(x509Authorities)
			require.Equal(t, tt.expectedX509Authorities, x509AuthoritiesIDs)

			require.Equal(t, tt.reuseToken, p.reuseToken)

			if p.cc.clientParams.Namespace != "" {
				headers := p.vc.vaultClient.Headers()
				require.Equal(t, p.cc.clientParams.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestMintX509CAErrorFromVaultWhenSigning(t *testing.T) {
	fakeVaultServer := setupFakeVautServer()

	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponseNotRenewable)
	fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
	fakeVaultServer.AppRoleAuthResponseCode = 200
	fakeVaultServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponseNotRenewable)
	fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	fakeVaultServer.LookupSelfResponseCode = 200
	// Expect error
	fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	fakeVaultServer.SignIntermediateResponseCode = 500
	fakeVaultServer.SignIntermediateResponse = []byte("fake-error")

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

	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	x509CA, x509Authorities, stream, err := v1.MintX509CA(context.Background(), csr.Raw, 3600)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "upstreamauthority(vault): fails to sign intermediate: Error making API request.")
	assert.Nil(t, x509CA)
	assert.Nil(t, x509Authorities)
	assert.Nil(t, stream)
}

func TestMintX509CAInvalidSigningResponse(t *testing.T) {
	fakeVaultServer := setupFakeVautServer()
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	fakeVaultServer.LookupSelfResponseCode = 200
	fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	fakeVaultServer.SignIntermediateResponseCode = 200
	fakeVaultServer.SignIntermediateResponse = []byte(testInvalidSignIntermediateResponse)

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

	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	// require.Contains(err.Error(), "failed to parse")
	x509CA, x509Authorities, stream, err := v1.MintX509CA(context.Background(), csr.Raw, 3600)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "upstreamauthority(vault): failed to parse Root CA certificate:")
	assert.Nil(t, x509CA)
	assert.Nil(t, x509Authorities)
	assert.Nil(t, stream)
}

func TestMintX509CA_InvalidCSR(t *testing.T) {
	fakeVaultServer := setupFakeVautServer()
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
	fakeVaultServer := setupFakeVautServer()
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

func setupFakeVautServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
	fakeVaultServer.ServerCertificatePemPath = testServerCert
	fakeVaultServer.ServerKeyPemPath = testServerKey
	fakeVaultServer.RenewResponseCode = 200
	fakeVaultServer.RenewResponse = []byte(testRenewResponse)
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
