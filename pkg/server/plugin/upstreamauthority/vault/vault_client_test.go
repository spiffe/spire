package vault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"

	"github.com/hashicorp/go-hclog"

	vapi "github.com/hashicorp/vault/api"

	"github.com/spiffe/spire/test/spiretest"
)

const (
	testRootCert          = "_test_data/keys/EC/root_cert.pem"
	testInvalidRootCert   = "_test_data/keys/EC/invalid_root_cert.pem"
	testServerCert        = "_test_data/keys/EC/server_cert.pem"
	testServerKey         = "_test_data/keys/EC/server_key.pem"
	testClientCert        = "_test_data/keys/EC/client_cert.pem"
	testClientKey         = "_test_data/keys/EC/client_key.pem"
	testInvalidClientCert = "_test_data/keys/EC/invalid_client_cert.pem"
	testInvalidClientKey  = "_test_data/keys/EC/invalid_client_key.pem"
	testReqCSR            = "_test_data/keys/EC/intermediate_csr.pem"
)

func testClientCertificatePair() (tls.Certificate, error) {
	cert, err := ioutil.ReadFile(testClientCert)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ioutil.ReadFile(testClientKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(cert, key)
}

func testRootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(testRootCert)
	if err != nil {
		return nil, err
	}
	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, err
	}
	return pool, nil
}

func TestVaultClient(t *testing.T) {
	spiretest.Run(t, new(VaultClientSuite))
}

type VaultClientSuite struct {
	spiretest.Suite

	fakeVaultServer *FakeVaultServerConfig
}

func (vcs *VaultClientSuite) SetupTest() {
	vcs.fakeVaultServer = NewFakeVaultServerConfig()
	vcs.fakeVaultServer.ServerCertificatePemPath = testServerCert
	vcs.fakeVaultServer.ServerKeyPemPath = testServerKey
	vcs.fakeVaultServer.RenewResponseCode = 200
	vcs.fakeVaultServer.RenewResponse = []byte(testRenewResponse)
}

func (vcs *VaultClientSuite) Test_NewClientConfig_WithDefaultMountPoint() {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "", // Expect the default value to be used.
		Token:                 "test-token",
		CertAuthMountPoint:    "", // Expect the default value to be used.
		AppRoleAuthMountPoint: "", // Expect the default value to be used.
	}

	cc, err := NewClientConfig(p, hclog.Default())
	vcs.Require().NoError(err)
	vcs.Require().Equal(defaultPKIMountPoint, cc.clientParams.PKIMountPoint)
	vcs.Require().Equal(defaultCertMountPoint, cc.clientParams.CertAuthMountPoint)
	vcs.Require().Equal(defaultAppRoleMountPoint, cc.clientParams.AppRoleAuthMountPoint)
}

func (vcs *VaultClientSuite) Test_NewClientConfig_WithGivenMontPoint() {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "test-pki",
		Token:                 "test-token",
		CertAuthMountPoint:    "test-tls-cert", // Expect the default value to be used.
		AppRoleAuthMountPoint: "test-approle",
	}

	cc, err := NewClientConfig(p, hclog.Default())
	vcs.Require().NoError(err)
	vcs.Require().Equal("test-pki", cc.clientParams.PKIMountPoint)
	vcs.Require().Equal("test-tls-cert", cc.clientParams.CertAuthMountPoint)
	vcs.Require().Equal("test-approle", cc.clientParams.AppRoleAuthMountPoint)
}

func (vcs *VaultClientSuite) Test_NewAuthenticatedClient_CertAuth() {
	vcs.fakeVaultServer.CertAuthResponseCode = 200
	vcs.fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     testRootCert,
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	_, err = cc.NewAuthenticatedClient(CERT)
	vcs.Require().NoError(err)
}

func (vcs *VaultClientSuite) Test_NewAuthenticatedClient_TokenAuth() {
	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	cp := &ClientParams{
		VaultAddr:  fmt.Sprintf("https://%v/", addr),
		CACertPath: testRootCert,
		Token:      "test-token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	client, err := cc.NewAuthenticatedClient(TOKEN)
	vcs.Require().NoError(err)
	vcs.Require().Equal("test-token", client.vaultClient.Token())
}

func (vcs *VaultClientSuite) Test_NewAuthenticatedClient_AppRoleAuth() {
	vcs.fakeVaultServer.AppRoleAuthResponseCode = 200
	vcs.fakeVaultServer.AppRoleAuthResponse = []byte(testAppRoleAuthResponse)

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	cp := &ClientParams{
		VaultAddr:       fmt.Sprintf("https://%v/", addr),
		CACertPath:      testRootCert,
		AppRoleID:       "test-approle-id",
		AppRoleSecretID: "test-approle-secret-id",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	_, err = cc.NewAuthenticatedClient(APPROLE)
	vcs.Require().NoError(err)
}

func (vcs *VaultClientSuite) Test_NewAuthenticatedClient_CertAuthFailed() {
	vcs.fakeVaultServer.CertAuthResponseCode = 500

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	retry := 0 // Disable retry
	cp := &ClientParams{
		MaxRetries:     &retry,
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     testRootCert,
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
	}

	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	_, err = cc.NewAuthenticatedClient(CERT)
	vcs.Require().Error(err)
}

func (vcs *VaultClientSuite) Test_NewAuthenticatedClient_AppRoleAuthFailed() {
	vcs.fakeVaultServer.AppRoleAuthResponseCode = 500

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	retry := 0 // Disable retry
	cp := &ClientParams{
		MaxRetries:      &retry,
		VaultAddr:       fmt.Sprintf("https://%v/", addr),
		CACertPath:      testRootCert,
		AppRoleID:       "test-approle-id",
		AppRoleSecretID: "test-approle-secret-id",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	_, err = cc.NewAuthenticatedClient(APPROLE)
	vcs.Require().Error(err)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_WithCertAuth() {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().NoError(err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	cert, err := tcc.GetClientCertificate(&tls.CertificateRequestInfo{})
	vcs.Require().NoError(err)

	testCert, err := testClientCertificatePair()
	vcs.Require().NoError(err)
	vcs.Require().Equal(testCert.Certificate, cert.Certificate)

	testPool, err := testRootCAs()
	vcs.Require().NoError(err)
	vcs.Require().Equal(testPool, tcc.RootCAs)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_WithTokenAuth() {
	cp := &ClientParams{
		VaultAddr:  "http://example.org:8200",
		CACertPath: testRootCert,
		Token:      "test-token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().NoError(err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	vcs.Require().Nil(tcc.GetClientCertificate)

	testPool, err := testRootCAs()
	vcs.Require().NoError(err)
	vcs.Require().Equal(testPool, tcc.RootCAs)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_WithAppRoleAuth() {
	cp := &ClientParams{
		VaultAddr:       "http://example.org:8200",
		CACertPath:      testRootCert,
		AppRoleID:       "test-approle-id",
		AppRoleSecretID: "test-approle-secret",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().NoError(err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	vcs.Require().Nil(tcc.GetClientCertificate)

	testPool, err := testRootCAs()
	vcs.Require().NoError(err)
	vcs.Require().Equal(testPool, tcc.RootCAs)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_InvalidCACert() {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testInvalidRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().Error(err)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_InvalidClientKey() {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testInvalidClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().Error(err)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_InvalidClientCert() {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testInvalidClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().Error(err)
}

func (vcs *VaultClientSuite) Test_ConfigureTLS_Require_ClientCertAndKey() {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	vcs.Require().EqualError(err, "both client cert and client key are required")
}

func (vcs *VaultClientSuite) Test_SignIntermediate() {
	vcs.fakeVaultServer.CertAuthResponseCode = 200
	vcs.fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	vcs.fakeVaultServer.SignIntermediateResponseCode = 200
	vcs.fakeVaultServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     testRootCert,
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
	}

	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	client, err := cc.NewAuthenticatedClient(CERT)
	vcs.Require().NoError(err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	vcs.Require().NoError(err)

	resp, err := client.SignIntermediate(testTTL, csr)
	vcs.Require().NoError(err)
	vcs.Require().NotNil(resp.CACertPEM)
	vcs.Require().NotNil(resp.CACertChainPEM)
	vcs.Require().NotNil(resp.CertPEM)
}

func (vcs *VaultClientSuite) Test_SignIntermediate_ErrorFromEndpoint() {
	vcs.fakeVaultServer.CertAuthResponseCode = 200
	vcs.fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	vcs.fakeVaultServer.SignIntermediateResponseCode = 500
	vcs.fakeVaultServer.SignIntermediateResponse = []byte("test error")

	s, addr, err := vcs.fakeVaultServer.NewTLSServer()
	vcs.Require().NoError(err)

	s.Start()
	defer s.Close()

	retry := 0 // Disable retry
	cp := &ClientParams{
		MaxRetries:     &retry,
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     testRootCert,
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
	}

	cc, err := NewClientConfig(cp, hclog.Default())
	vcs.Require().NoError(err)

	client, err := cc.NewAuthenticatedClient(CERT)
	vcs.Require().NoError(err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	vcs.Require().NoError(err)

	_, err = client.SignIntermediate(testTTL, csr)
	vcs.Require().Error(err)
}
