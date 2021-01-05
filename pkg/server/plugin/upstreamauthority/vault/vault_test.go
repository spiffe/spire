package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
)

func init() {
	os.Unsetenv(envVaultAddr)
	os.Unsetenv(envVaultToken)
	os.Unsetenv(envVaultClientCert)
	os.Unsetenv(envVaultClientKey)
	os.Unsetenv(envVaultCACert)
	os.Unsetenv(envVaultAppRoleID)
	os.Unsetenv(envVaultAppRoleSecretID)
}

func TestVaultPlugin(t *testing.T) {
	spiretest.Run(t, new(VaultPluginSuite))
}

type VaultPluginSuite struct {
	spiretest.Suite

	fakeVaultServer *FakeVaultServerConfig
	plugin          upstreamauthority.Plugin
}

func (vps *VaultPluginSuite) SetupTest() {
	vps.fakeVaultServer = NewFakeVaultServerConfig()
	vps.fakeVaultServer.ServerCertificatePemPath = testServerCert
	vps.fakeVaultServer.ServerKeyPemPath = testServerKey
	vps.fakeVaultServer.RenewResponseCode = 200
	vps.fakeVaultServer.RenewResponse = []byte(testRenewResponse)
}

func (vps *VaultPluginSuite) Test_Configure() {
	vps.fakeVaultServer.CertAuthResponseCode = 200
	vps.fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	vps.fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
	vps.fakeVaultServer.AppRoleAuthResponseCode = 200
	vps.fakeVaultServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponse)
	vps.fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	for _, c := range []struct {
		name                  string
		configTmpl            string
		err                   string
		wantAuth              AuthMethod
		wantNamespaceIsNotNil bool
		envKeyVal             map[string]string
	}{
		{
			name:       "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl: testTokenAuthConfigTpl,
			wantAuth:   TOKEN,
		},
		{
			name:       "Configure plugin with Token authentication params given as environment variables",
			configTmpl: testTokenAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultToken: "test-token",
			},
			wantAuth: TOKEN,
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl: testCertAuthConfigTpl,
			wantAuth:   CERT,
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given as environment variables",
			configTmpl: testCertAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultClientCert: "_test_data/keys/EC/client_cert.pem",
				envVaultClientKey:  "_test_data/keys/EC/client_key.pem",
			},
			wantAuth: CERT,
		},
		{
			name:       "Configure plugin with AppRole authenticate params given in config file",
			configTmpl: testAppRoleAuthConfigTpl,
			wantAuth:   APPROLE,
		},
		{
			name:       "Configure plugin with AppRole authentication params given as environment variables",
			configTmpl: testAppRoleAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				envVaultAppRoleID:       "test-approle-id",
				envVaultAppRoleSecretID: "test-approle-secret-id",
			},
			wantAuth: APPROLE,
		},
		{
			name:       "Multiple authentication methods configured",
			configTmpl: testMultipleAuthConfigsTpl,
			err:        "only one authentication method can be configured",
		},
		{
			name:       "Pass VaultAddr via the environment variable",
			configTmpl: testConfigWithVaultAddrEnvTpl,
			envKeyVal: map[string]string{
				envVaultAddr: fmt.Sprintf("https://%v/", addr),
			},
			wantAuth: TOKEN,
		},
		{
			name:                  "Configure plugin with given namespace",
			configTmpl:            testNamespaceConfigTpl,
			wantAuth:              TOKEN,
			wantNamespaceIsNotNil: true,
		},
	} {
		c := c
		vps.Run(c.name, func() {
			defer func() {
				for k := range c.envKeyVal {
					os.Unsetenv(k)
				}
			}()
			for k, v := range c.envKeyVal {
				os.Setenv(k, v)
			}

			p := vps.newPlugin()
			req := vps.getTestConfigureRequest(fmt.Sprintf("https://%v/", addr), c.configTmpl)
			ctx := context.Background()
			_, err = p.Configure(ctx, req)
			if c.err != "" {
				vps.Require().EqualError(err, c.err)
				return
			}

			vps.Require().NotNil(p.cc)
			vps.Require().NotNil(p.cc.clientParams)

			switch c.wantAuth {
			case TOKEN:
				vps.Require().NotNil(p.cc.clientParams.Token)
			case CERT:
				vps.Require().NotNil(p.cc.clientParams.CertAuthMountPoint)
				vps.Require().NotNil(p.cc.clientParams.ClientCertPath)
				vps.Require().NotNil(p.cc.clientParams.ClientKeyPath)
			case APPROLE:
				vps.Require().NotNil(p.cc.clientParams.AppRoleAuthMountPoint)
				vps.Require().NotNil(p.cc.clientParams.AppRoleID)
				vps.Require().NotNil(p.cc.clientParams.AppRoleSecretID)
			}

			if c.wantNamespaceIsNotNil {
				vps.Require().NotNil(p.cc.clientParams.Namespace)
			}
		})
	}
}

func (vps *VaultPluginSuite) Test_Configure_Error_InvalidConfig() {
	ctx := context.Background()
	req := &plugin.ConfigureRequest{
		Configuration: "invalid-config",
	}

	p := vps.newPlugin()

	_, err := p.Configure(ctx, req)
	vps.Require().Error(err)
	vps.Require().Contains(err.Error(), "failed to decode configuration file")
}

func (vps *VaultPluginSuite) Test_MintX509CA() {
	for _, c := range []struct {
		name                 string
		lookupSelfResp       []byte
		certAuthResp         []byte
		appRoleAuthResp      []byte
		signIntermediateResp []byte
		config               *PluginConfig
		authMethod           AuthMethod
		reuseToken           bool
		err                  string
	}{
		{
			name:                 "Mint X509CA SVID with Token authentication",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				PKIMountPoint: "test-pki",
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod: TOKEN,
			reuseToken: true,
		},
		{
			name:                 "Mint X509CA SVID with Token authentication / Token is not renewable",
			lookupSelfResp:       []byte(testLookupSelfResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				PKIMountPoint: "test-pki",
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod: TOKEN,
		},
		{
			name:                 "Mint X509CA SVID with Token authentication / Token never expire",
			lookupSelfResp:       []byte(testLookupSelfResponseNeverExpire),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				PKIMountPoint: "test-pki",
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod: TOKEN,
			reuseToken: true,
		},
		{
			name:                 "Mint X509CA SVID with TLS cert authentication",
			certAuthResp:         []byte(testCertAuthResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     "_test_data/keys/EC/client_cert.pem",
					ClientKeyPath:      "_test_data/keys/EC/client_key.pem",
				},
			},
			authMethod: CERT,
			reuseToken: true,
		},
		{
			name:                 "Mint X509CA SVID with AppRole authentication",
			appRoleAuthResp:      []byte(testAppRoleAuthResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod: APPROLE,
			reuseToken: true,
		},
		{
			name:                 "Mint X509CA SVID with TLS cert authentication / Token is not renewable",
			certAuthResp:         []byte(testCertAuthResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				CertAuth: &CertAuthConfig{
					CertAuthMountPoint: "test-cert-auth",
					CertAuthRoleName:   "test",
					ClientCertPath:     "_test_data/keys/EC/client_cert.pem",
					ClientKeyPath:      "_test_data/keys/EC/client_key.pem",
				},
			},
			authMethod: CERT,
		},
		{
			name:                 "Mint X509CA SVID with AppRole authentication / Token is not renewable",
			appRoleAuthResp:      []byte(testAppRoleAuthResponseNotRenewable),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				PKIMountPoint: "test-pki",
				AppRoleAuth: &AppRoleAuthConfig{
					AppRoleMountPoint: "test-approle-auth",
					RoleID:            "test-approle-id",
					SecretID:          "test-approle-secret-id",
				},
			},
			authMethod: APPROLE,
		},
		{
			name:                 "Mint X509CA SVID with Namespace",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponse),
			config: &PluginConfig{
				Namespace:     "test-ns",
				PKIMountPoint: "test-pki",
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod: TOKEN,
			reuseToken: true,
		},
		{
			name:                 "Mint X509CA SVID against the RootCA Vault",
			lookupSelfResp:       []byte(testLookupSelfResponse),
			signIntermediateResp: []byte(testSignIntermediateResponseNoChain),
			config: &PluginConfig{
				PKIMountPoint: "test-pki",
				CACertPath:    "_test_data/keys/EC/root_cert.pem",
				TokenAuth: &TokenAuthConfig{
					Token: "test-token",
				},
			},
			authMethod: TOKEN,
			reuseToken: true,
		},
	} {
		c := c
		vps.Run(c.name, func() {
			vps.fakeVaultServer.CertAuthResponseCode = 200
			vps.fakeVaultServer.CertAuthResponse = c.certAuthResp
			vps.fakeVaultServer.CertAuthReqEndpoint = "/v1/auth/test-cert-auth/login"
			vps.fakeVaultServer.AppRoleAuthResponseCode = 200
			vps.fakeVaultServer.AppRoleAuthResponse = c.appRoleAuthResp
			vps.fakeVaultServer.AppRoleAuthReqEndpoint = "/v1/auth/test-approle-auth/login"
			vps.fakeVaultServer.LookupSelfResponse = c.lookupSelfResp
			vps.fakeVaultServer.LookupSelfResponseCode = 200
			vps.fakeVaultServer.SignIntermediateResponseCode = 200
			vps.fakeVaultServer.SignIntermediateResponse = c.signIntermediateResp
			vps.fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"

			s, addr, err := vps.fakeVaultServer.NewTLSServer()
			vps.Require().NoError(err)

			s.Start()
			defer s.Close()

			p := vps.newPlugin()
			c.config.VaultAddr = fmt.Sprintf("https://%s", addr)
			cp := genClientParams(c.authMethod, c.config)
			cc, err := NewClientConfig(cp, p.logger)
			vps.Require().NoError(err)
			p.cc = cc
			p.authMethod = c.authMethod

			vps.LoadPlugin(builtin(p), &vps.plugin)

			req := vps.loadMintX509CARequestFromTestFile()
			res, err := vps.mintX509CA(req)
			vps.Require().NoError(err)
			vps.Require().NotNil(res)

			for _, certDER := range res.X509CaChain {
				cert, err := x509.ParseCertificate(certDER)
				vps.Require().NoError(err)
				vps.Require().NotNil(cert)
			}

			for _, upstreamDER := range res.UpstreamX509Roots {
				upstream, err := x509.ParseCertificate(upstreamDER)
				vps.Require().NoError(err)
				vps.Require().NotNil(upstream)
			}

			vps.Require().Equal(c.reuseToken, p.reuseToken)

			if p.cc.clientParams.Namespace != "" {
				headers := p.vc.vaultClient.Headers()
				vps.Require().Equal(p.cc.clientParams.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func (vps *VaultPluginSuite) Test_MintX509CA_ErrorFromVault() {
	vps.fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vps.fakeVaultServer.SignIntermediateResponseCode = 500
	vps.fakeVaultServer.SignIntermediateResponse = []byte("fake-error")

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.cc = vps.getFakeClientConfig(addr)

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
}

func (vps *VaultPluginSuite) Test_MintX509CA_InvalidVaultResponse() {
	vps.fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	vps.fakeVaultServer.LookupSelfResponseCode = 200
	vps.fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vps.fakeVaultServer.SignIntermediateResponseCode = 200
	vps.fakeVaultServer.SignIntermediateResponse = []byte(testInvalidSignIntermediateResponse)

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.cc = vps.getFakeClientConfig(addr)
	p.authMethod = TOKEN

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
	vps.Require().Contains(err.Error(), "failed to parse")
}

func (vps *VaultPluginSuite) Test_MintX509CA_InvalidCSR() {
	vps.fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponse)
	vps.fakeVaultServer.LookupSelfResponseCode = 200

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.cc = vps.getFakeClientConfig(addr)
	p.authMethod = TOKEN

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()
	req.Csr = []byte("invalid-csr") //overwrite the CSR value

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
	vps.Require().Contains(err.Error(), "failed to parse CSR data")
}

func (vps *VaultPluginSuite) mintX509CA(req *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := vps.plugin.MintX509CA(ctx, req)
	vps.Require().NoError(err)
	vps.Require().NotNil(stream)

	response, err := stream.Recv()
	if err == nil {
		_, eof := stream.Recv()
		vps.Require().Equal(io.EOF, eof)
	}

	return response, err
}

func (vps *VaultPluginSuite) newPlugin() *Plugin {
	p := New()
	p.SetLogger(hclog.Default())
	return p
}

func (vps *VaultPluginSuite) getTestConfigureRequest(addr string, tpl string) *plugin.ConfigureRequest {
	t, err := template.New("plugin config").Parse(tpl)
	vps.Require().NoError(err)

	cp := &struct{ Addr string }{Addr: addr}

	var c bytes.Buffer
	err = t.Execute(&c, cp)
	vps.Require().NoError(err)

	return &plugin.ConfigureRequest{
		Configuration: c.String(),
	}
}

func (vps *VaultPluginSuite) loadMintX509CARequestFromTestFile() *upstreamauthority.MintX509CARequest {
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	vps.Require().NoError(err)

	return &upstreamauthority.MintX509CARequest{
		Csr:          csr.Raw,
		PreferredTtl: 3600,
	}
}

func (vps *VaultPluginSuite) getFakeClientConfig(addr string) *ClientConfig {
	retry := 0
	cp := &ClientParams{
		MaxRetries:    &retry,
		VaultAddr:     fmt.Sprintf("https://%v/", addr),
		CACertPath:    testRootCert,
		PKIMountPoint: "test-pki",
		Token:         "test-token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vps.Require().NoError(err)

	return cc
}
