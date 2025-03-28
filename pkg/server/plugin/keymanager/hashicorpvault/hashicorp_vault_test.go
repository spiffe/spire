package hashicorpvault

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/hashicorp/vault/sdk/helper/consts"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
)

const (
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
)

func TestPluginConfigure(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		configTmpl               string
		plainConfig              string
		expectMsgPrefix          string
		expectCode               codes.Code
		wantAuth                 AuthMethod
		expectNamespace          string
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
		expectTransitEnginePath  string
	}{
		{
			name:                    "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl:              testTokenAuthConfigTpl,
			wantAuth:                TOKEN,
			expectToken:             "test-token",
			expectTransitEnginePath: "transit",
		},
		{
			name:       "Configure plugin with Token authentication params given as environment variables",
			configTmpl: testTokenAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultToken: "test-token",
			},
			wantAuth:                TOKEN,
			expectToken:             "test-token",
			expectTransitEnginePath: "transit",
		},
		{
			name:                     "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl:               testCertAuthConfigTpl,
			wantAuth:                 CERT,
			expectCertAuthMountPoint: "test-cert-auth",
			expectClientCertPath:     "testdata/client-cert.pem",
			expectClientKeyPath:      "testdata/client-key.pem",
			expectTransitEnginePath:  "transit",
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
			expectTransitEnginePath:  "transit",
		},
		{
			name:                    "Configure plugin with AppRole authenticate params given in config file",
			configTmpl:              testAppRoleAuthConfigTpl,
			wantAuth:                APPROLE,
			appRoleAuthMountPoint:   "test-approle-auth",
			appRoleID:               "test-approle-id",
			appRoleSecretID:         "test-approle-secret-id",
			expectTransitEnginePath: "transit",
		},
		{
			name:       "Configure plugin with AppRole authentication params given as environment variables",
			configTmpl: testAppRoleAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultAppRoleID:       "test-approle-id",
				envVaultAppRoleSecretID: "test-approle-secret-id",
			},
			wantAuth:                APPROLE,
			appRoleAuthMountPoint:   "test-approle-auth",
			appRoleID:               "test-approle-id",
			appRoleSecretID:         "test-approle-secret-id",
			expectTransitEnginePath: "transit",
		},
		{
			name:                    "Configure plugin with Kubernetes authentication params given in config file",
			configTmpl:              testK8sAuthConfigTpl,
			wantAuth:                K8S,
			expectK8sAuthMountPoint: "test-k8s-auth",
			expectK8sAuthTokenPath:  "testdata/k8s/token",
			expectK8sAuthRoleName:   "my-role",
			expectTransitEnginePath: "transit",
		},
		{
			name:                    "Multiple authentication methods configured",
			configTmpl:              testMultipleAuthConfigsTpl,
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "only one authentication method can be configured",
			expectTransitEnginePath: "transit",
		},
		{
			name:                    "Configure plugin with transit engine path given in config file",
			configTmpl:              testConfigWithTransitEnginePathTpl,
			wantAuth:                TOKEN,
			expectToken:             "test-token",
			expectTransitEnginePath: "test-path",
		},
		{
			name:       "Configure plugin with transit engine path given as environment variables",
			configTmpl: testConfigWithTransitEnginePathEnvTpl,
			envKeyVal: map[string]string{
				envVaultTransitEnginePath: "test-path",
			},
			wantAuth:                TOKEN,
			expectToken:             "test-token",
			expectTransitEnginePath: "test-path",
		},
		{
			name:                    "Configure plugin with namespace given in config file",
			configTmpl:              testNamespaceConfigTpl,
			wantAuth:                TOKEN,
			expectNamespace:         "test-ns",
			expectTransitEnginePath: "transit",
			expectToken:             "test-token",
		},
		{
			name:       "Configure plugin with given namespace given as environment variable",
			configTmpl: testNamespaceEnvTpl,
			wantAuth:   TOKEN,
			envKeyVal: map[string]string{
				envVaultNamespace: "test-ns",
			},
			expectNamespace:         "test-ns",
			expectTransitEnginePath: "transit",
			expectToken:             "test-token",
		},
		{
			name:                    "Malformed configuration",
			plainConfig:             "invalid-config",
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "unable to decode configuration:",
			expectTransitEnginePath: "transit",
		},
		{
			name:                    "Required parameters are not given / k8s_auth_role_name",
			configTmpl:              testK8sAuthNoRoleNameTpl,
			wantAuth:                K8S,
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "k8s_auth_role_name is required",
			expectTransitEnginePath: "transit",
		},
		{
			name:                    "Required parameters are not given / token_path",
			configTmpl:              testK8sAuthNoTokenPathTpl,
			wantAuth:                K8S,
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "token_path is required",
			expectTransitEnginePath: "transit",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer := setupSuccessFakeVaultServer(tt.expectTransitEnginePath)
			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			p := New()
			p.hooks.lookupEnv = func(s string) (string, bool) {
				if len(tt.envKeyVal) == 0 {
					return "", false
				}
				v, ok := tt.envKeyVal[s]
				return v, ok
			}

			plainConfig := tt.plainConfig
			if tt.plainConfig == "" {
				plainConfig = getTestConfigureRequest(t, fmt.Sprintf("https://%v/", addr), createKeyIdentifierFile(t), tt.configTmpl)
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

			require.Equal(t, tt.expectTransitEnginePath, p.cc.clientParams.TransitEnginePath)
			require.Equal(t, tt.expectNamespace, p.cc.clientParams.Namespace)
		})
	}
}

func TestValidate(t *testing.T) {
	ctx := context.Background()

	for _, tt := range []struct {
		name             string
		hclConfiguration string
		expectResp       *configv1.ValidateResponse
	}{
		{
			name:             "Valid configuration",
			hclConfiguration: testTokenAuthConfigTpl,
			expectResp: &configv1.ValidateResponse{
				Valid: true,
				Notes: nil,
			},
		},
		{
			name:             "Unable to parse configuration",
			hclConfiguration: "invalid!",
			expectResp: &configv1.ValidateResponse{
				Valid: false,
				Notes: []string{
					"unable to decode configuration: At 1:8: illegal char",
				},
			},
		},
		{
			name: "Unable to persist Server ID",
			hclConfiguration: `
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
`, // #nosec G101
			expectResp: &configv1.ValidateResponse{
				Valid: false,
				Notes: []string{
					"unable to decode configuration: rpc error: code = Internal desc = failed to persist server ID on path: open : no such file or directory",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: spiffeid.RequireTrustDomainFromString("localhost").Name(),
				},
				HclConfiguration: tt.hclConfiguration,
			}

			p := new(Plugin)
			resp, err := p.Validate(ctx, req)
			require.NoError(t, err)
			require.Equal(t, tt.expectResp, resp)
		})
	}
}

func TestPluginGenerateKey(t *testing.T) {
	successfulConfig := &Config{
		TransitEnginePath: "test-transit",
		CACertPath:        "testdata/root-cert.pem",
		TokenAuth: &TokenAuthConfig{
			Token: "test-token",
		},
	}

	for _, tt := range []struct {
		name            string
		config          *Config
		authMethod      AuthMethod
		expectCode      codes.Code
		expectMsgPrefix string
		id              string
		keyType         keymanager.KeyType

		fakeServer func() *FakeVaultServerConfig
	}{
		{
			name:       "Generate EC P-256 key with token auth",
			id:         "x509-CA-A",
			keyType:    keymanager.ECP256,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}

				return fakeServer
			},
		},
		{
			name:       "Generate P-384 key with token auth",
			id:         "x509-CA-A",
			keyType:    keymanager.ECP384,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseP384)

				return fakeServer
			},
		},
		{
			name:       "Generate RSA 2048 key with token auth",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
		},
		{
			name:       "Generate RSA 4096 key with token auth",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA4096,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA4096)

				return fakeServer
			},
		},
		{
			name:       "Generate key with missing id",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "keymanager(hashicorp_vault): key id is required",
		},
		{
			name:       "Generate key with missing key type",
			id:         "x509-CA-A",
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "keymanager(hashicorp_vault): key type is required",
		},
		{
			name:       "Generate key with unsupported key type",
			id:         "x509-CA-A",
			keyType:    100,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): facade does not support key type \"UNKNOWN(100)\"",
		},
		{
			name:       "Malformed get key response",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte("error")

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): failed to get transit engine key: invalid character",
		},
		{
			name:       "Malformed create key response",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.CreateKeyResponse = []byte("error")

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): failed to create transit engine key: invalid character",
		},
		{
			name:       "Bad get key response code",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponseCode = 500

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): failed to get transit engine key: Error making API request.",
		},
		{
			name:       "Bad create key response code",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.CreateKeyResponseCode = 500

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): failed to create transit engine key: Error making API request.",
		},
		{
			name:       "Malformed key",
			id:         "x509-CA-A",
			keyType:    keymanager.RSA2048,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseMalformed)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "keymanager(hashicorp_vault): unable to decode PEM key",
		},
		{
			name:       "Generate key with existing SPIRE key id",
			id:         "x509-CA-A",
			keyType:    keymanager.ECP256,
			config:     successfulConfig,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("test-transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeysResponse = []byte(testGetKeysResponseOneKey)

				return fakeServer
			},
		},
	} {
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
				tt.config.KeyIdentifierFile = createKeyIdentifierFile(t)
				tt.config.VaultAddr = fmt.Sprintf("https://%s", addr)
				cp, err := p.genClientParams(tt.authMethod, tt.config)
				require.NoError(t, err)
				cc, err := NewClientConfig(cp, p.logger)
				require.NoError(t, err)
				p.cc = cc
				options = append(options, plugintest.ConfigureJSON(tt.config))
			}
			p.authMethod = tt.authMethod

			v1 := new(keymanager.V1)
			plugintest.Load(t, builtin(p), v1,
				options...,
			)

			key, err := v1.GenerateKey(context.Background(), tt.id, tt.keyType)

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				require.Nil(t, key)
				return
			}

			require.NotNil(t, key)
			require.Equal(t, tt.id, key.ID())

			if p.cc.clientParams.Namespace != "" {
				headers := p.vc.vaultClient.Headers()
				require.Equal(t, p.cc.clientParams.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestPluginGetKey(t *testing.T) {
	for _, tt := range []struct {
		name            string
		config          *Config
		configTmpl      string
		authMethod      AuthMethod
		expectCode      codes.Code
		expectMsgPrefix string
		id              string

		fakeServer func() *FakeVaultServerConfig
	}{
		{
			name:       "Get EC P-256 key with token auth",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}

				return fakeServer
			},
		},
		{
			name:       "Get P-384 key with token auth",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseP384)

				return fakeServer
			},
		},
		{
			name:       "Get RSA 2048 key with token auth",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
		},
		{
			name:       "Get RSA 4096 key with token auth",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA4096)

				return fakeServer
			},
		},
		{
			name:       "Get key with missing id",
			configTmpl: testTokenAuthConfigTpl,
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseRSA2048)

				return fakeServer
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "keymanager(hashicorp_vault): key id is required",
		},
		{
			name:       "Malformed get key response",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte("error")

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "failed to get transit engine key:",
		},
		{
			name:       "Bad get key response code",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponseCode = 500

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "failed to get transit engine key:",
		},
		{
			name:       "Malformed key",
			configTmpl: testTokenAuthConfigTpl,
			id:         "x509-CA-A",
			authMethod: TOKEN,
			fakeServer: func() *FakeVaultServerConfig {
				fakeServer := setupSuccessFakeVaultServer("transit")
				fakeServer.LookupSelfResponse = []byte(testLookupSelfResponse)
				fakeServer.CertAuthResponse = []byte{}
				fakeServer.AppRoleAuthResponse = []byte{}
				fakeServer.GetKeyResponse = []byte(testGetKeyResponseMalformed)

				return fakeServer
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "unable to decode PEM key",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer := tt.fakeServer()

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			p := New()
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.Configure(getTestConfigureRequest(t, fmt.Sprintf("https://%v/", addr), createKeyIdentifierFile(t), tt.configTmpl)),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			}

			v1 := new(keymanager.V1)
			plugintest.Load(t, builtin(p), v1,
				options...,
			)

			if err != nil {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
				return
			}

			key, err := v1.GetKey(context.Background(), tt.id)

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				require.Nil(t, key)
				return
			}

			require.NotNil(t, key)
			require.Equal(t, tt.id, key.ID())

			if p.cc.clientParams.Namespace != "" {
				headers := p.vc.vaultClient.Headers()
				require.Equal(t, p.cc.clientParams.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

// TODO: Should the Sign function also be tested?

func getTestConfigureRequest(t *testing.T, addr string, keyIdentifierFile string, tpl string) string {
	templ, err := template.New("plugin config").Parse(tpl)
	require.NoError(t, err)

	cp := &struct {
		Addr              string
		KeyIdentifierFile string
	}{
		Addr:              addr,
		KeyIdentifierFile: keyIdentifierFile,
	}

	var c bytes.Buffer
	err = templ.Execute(&c, cp)
	require.NoError(t, err)

	return c.String()
}

func setupSuccessFakeVaultServer(transitEnginePath string) *FakeVaultServerConfig {
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

	fakeVaultServer.LookupSelfResponseCode = 200
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	fakeVaultServer.LookupSelfReqEndpoint = "GET /v1/auth/token/lookup-self"

	fakeVaultServer.CreateKeyResponseCode = 200
	fakeVaultServer.CreateKeyReqEndpoint = fmt.Sprintf("PUT /v1/%s/keys/{id}", transitEnginePath)

	fakeVaultServer.DeleteKeyResponseCode = 204
	fakeVaultServer.DeleteKeyReqEndpoint = fmt.Sprintf("DELETE /v1/%s/keys/{id}", transitEnginePath)

	fakeVaultServer.UpdateKeyConfigurationResponseCode = 204
	fakeVaultServer.UpdateKeyConfigurationReqEndpoint = fmt.Sprintf("PUT /v1/%s/keys/{id}/config", transitEnginePath)

	fakeVaultServer.GetKeyResponseCode = 200
	fakeVaultServer.GetKeyReqEndpoint = fmt.Sprintf("GET /v1/%s/keys/{id}", transitEnginePath)
	fakeVaultServer.GetKeyResponse = []byte(testGetKeyResponseP256)

	fakeVaultServer.GetKeysResponseCode = 200
	fakeVaultServer.GetKeysReqEndpoint = fmt.Sprintf("GET /v1/%s/keys", transitEnginePath)
	fakeVaultServer.GetKeysResponse = []byte(testGetKeysResponseOneKey)

	return fakeVaultServer
}

func setupFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
	fakeVaultServer.ServerCertificatePemPath = testServerCert
	fakeVaultServer.ServerKeyPemPath = testServerKey
	fakeVaultServer.RenewResponseCode = 200
	fakeVaultServer.RenewResponse = []byte(testRenewResponse)
	return fakeVaultServer
}

func createKeyIdentifierFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))
	err := os.WriteFile(tempFilePath, []byte(validServerID), 0o600)
	if err != nil {
		t.Error(err)
	}

	return tempFilePath
}
