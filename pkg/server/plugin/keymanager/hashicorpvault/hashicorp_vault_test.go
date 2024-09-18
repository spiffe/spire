package hashicorpvault

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"testing"
	"text/template"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
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
			wantAuth:                TOKEN,
			expectToken:             "test-token",
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

			require.Equal(t, tt.expectTransitEnginePath, p.cc.clientParams.TransitEnginePath)
			require.Equal(t, tt.expectNamespace, p.cc.clientParams.Namespace)
		})
	}
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
