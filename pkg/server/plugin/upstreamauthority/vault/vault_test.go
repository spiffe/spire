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
		name       string
		configTmpl string
		err        string
		envKeyVal  map[string]string
	}{
		{
			name:       "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl: testTokenAuthConfigTpl,
		},
		{
			name:       "Configure plugin with Token authentication params given as environment variables",
			configTmpl: testTokenAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				"VAULT_TOKEN": "test-token",
			},
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given in config file",
			configTmpl: testCertAuthConfigTpl,
		},
		{
			name:       "Configure plugin with Client Certificate authentication params given as environment variables",
			configTmpl: testCertAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				"VAULT_CLIENT_CERT": "_test_data/keys/EC/client_cert.pem",
				"VAULT_CLIENT_KEY":  "_test_data/keys/EC/client_key.pem",
			},
		},
		{
			name:       "Configure plugin with AppRole authenticate params given in config file",
			configTmpl: testAppRoleAuthConfigTpl,
		},
		{
			name:       "Configure plugin with AppRole authentication params given as environment variables",
			configTmpl: testAppRoleAuthConfigWithEnvTpl,
			envKeyVal: map[string]string{
				"VAULT_APPROLE_ID":        "test-approle-id",
				"VAULT_APPROLE_SECRET_ID": "test-approle-secret-id",
			},
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
			vps.Require().NotNil(p.vc.vaultClient.Token())
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
	vps.fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vps.fakeVaultServer.SignIntermediateResponseCode = 200
	vps.fakeVaultServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.vc = vps.getFakeVaultClient(addr)

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
	p.vc = vps.getFakeVaultClient(addr)

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
}

func (vps *VaultPluginSuite) Test_MintX509CA_InvalidVaultResponse() {
	vps.fakeVaultServer.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vps.fakeVaultServer.SignIntermediateResponseCode = 200
	vps.fakeVaultServer.SignIntermediateResponse = []byte(testInvalidSignIntermediateResponse)

	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.vc = vps.getFakeVaultClient(addr)

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
	vps.Require().Contains(err.Error(), "failed to parse")
}

func (vps *VaultPluginSuite) Test_MintX509CA_InvalidCSR() {
	s, addr, err := vps.fakeVaultServer.NewTLSServer()
	vps.Require().NoError(err)

	s.Start()
	defer s.Close()

	p := vps.newPlugin()
	p.vc = vps.getFakeVaultClient(addr)

	vps.LoadPlugin(builtin(p), &vps.plugin)
	req := vps.loadMintX509CARequestFromTestFile()
	req.Csr = []byte("invalid-csr") //overwrite the CSR value

	_, err = vps.mintX509CA(req)
	vps.Require().Error(err)
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

func (vps *VaultPluginSuite) getFakeVaultClient(addr string) *Client {
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

	client, err := cc.NewAuthenticatedClient(TOKEN)
	vps.Require().NoError(err)

	return client
}
