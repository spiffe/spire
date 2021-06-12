package vault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testRootCert          = "testdata/keys/EC/root_cert.pem"
	testInvalidRootCert   = "testdata/keys/EC/invalid_root_cert.pem"
	testServerCert        = "testdata/keys/EC/server_cert.pem"
	testServerKey         = "testdata/keys/EC/server_key.pem"
	testClientCert        = "testdata/keys/EC/client_cert.pem"
	testClientKey         = "testdata/keys/EC/client_key.pem"
	testInvalidClientCert = "testdata/keys/EC/invalid_client_cert.pem"
	testInvalidClientKey  = "testdata/keys/EC/invalid_client_key.pem"
	testReqCSR            = "testdata/keys/EC/intermediate_csr.pem"
)

func TestNewClientConfigWithDefaultMountPoint(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "", // Expect the default value to be used.
		Token:                 "test-token",
		CertAuthMountPoint:    "", // Expect the default value to be used.
		AppRoleAuthMountPoint: "", // Expect the default value to be used.
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, defaultPKIMountPoint, cc.clientParams.PKIMountPoint)
	require.Equal(t, defaultCertMountPoint, cc.clientParams.CertAuthMountPoint)
	require.Equal(t, defaultAppRoleMountPoint, cc.clientParams.AppRoleAuthMountPoint)
}

func TestNewClientConfigWithGivenMontPoint(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "test-pki",
		Token:                 "test-token",
		CertAuthMountPoint:    "test-tls-cert", // Expect the default value to be used.
		AppRoleAuthMountPoint: "test-approle",
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, "test-pki", cc.clientParams.PKIMountPoint)
	require.Equal(t, "test-tls-cert", cc.clientParams.CertAuthMountPoint)
	require.Equal(t, "test-approle", cc.clientParams.AppRoleAuthMountPoint)
}

func TestNewAuthenticatedClientCertAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	for _, tt := range []struct {
		name      string
		response  []byte
		reusable  bool
		namespace string
	}{
		{
			name:     "Cert Authentication success / Token is renewable",
			response: []byte(testCertAuthResponse),
			reusable: true,
		},
		{
			name:     "Cert Authentication success / Token is not renewable",
			response: []byte(testCertAuthResponseNotRenewable),
		},
		{
			name:      "Cert Authentication success / Token is renewable / Namespace is given",
			response:  []byte(testCertAuthResponse),
			reusable:  true,
			namespace: "test-ns",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer.CertAuthResponse = tt.response

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			cp := &ClientParams{
				VaultAddr:      fmt.Sprintf("https://%v/", addr),
				Namespace:      tt.namespace,
				CACertPath:     testRootCert,
				ClientCertPath: testClientCert,
				ClientKeyPath:  testClientKey,
			}
			cc, err := NewClientConfig(cp, hclog.Default())
			require.NoError(t, err)

			client, reusable, err := cc.NewAuthenticatedClient(CERT)
			require.NoError(t, err)
			require.Equal(t, tt.reusable, reusable)

			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestNewAuthenticatedClientTokenAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.LookupSelfResponseCode = 200
	for _, tt := range []struct {
		name            string
		token           string
		response        []byte
		reusable        bool
		namespace       string
		expectCode      codes.Code
		expectMsgPrefix string
	}{
		{
			name:     "Token Authentication success / Token never expire",
			token:    "test-token",
			response: []byte(testLookupSelfResponseNeverExpire),
			reusable: true,
		},
		{
			name:     "Token Authentication success / Token is renewable",
			token:    "test-token",
			response: []byte(testLookupSelfResponse),
			reusable: true,
		},
		{
			name:     "Token Authentication success / Token is not renewable",
			token:    "test-token",
			response: []byte(testLookupSelfResponseNotRenewable),
		},
		{
			name:      "Token Authentication success / Token is renewable / Namespace is given",
			token:     "test-token",
			response:  []byte(testCertAuthResponse),
			reusable:  true,
			namespace: "test-ns",
		},
		{
			name:            "Token Authentication error / Token is empty",
			token:           "",
			response:        []byte(testCertAuthResponse),
			reusable:        true,
			namespace:       "test-ns",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "token is empty",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer.LookupSelfResponse = tt.response

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			cp := &ClientParams{
				VaultAddr:  fmt.Sprintf("https://%v/", addr),
				Namespace:  tt.namespace,
				CACertPath: testRootCert,
				Token:      tt.token,
			}
			cc, err := NewClientConfig(cp, hclog.Default())
			require.NoError(t, err)

			client, reusable, err := cc.NewAuthenticatedClient(TOKEN)
			if tt.expectMsgPrefix != "" {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.reusable, reusable)
			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestNewAuthenticatedClientAppRoleAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.AppRoleAuthResponseCode = 200
	for _, tt := range []struct {
		name      string
		response  []byte
		reusable  bool
		namespace string
	}{
		{
			name:     "AppRole Authentication success / Token is renewable",
			response: []byte(testAppRoleAuthResponse),
			reusable: true,
		},
		{
			name:     "AppRole Authentication success / Token is not renewable",
			response: []byte(testAppRoleAuthResponseNotRenewable),
		},
		{
			name:      "AppRole Authentication success / Token is renewable / Namespace is given",
			response:  []byte(testAppRoleAuthResponse),
			reusable:  true,
			namespace: "test-ns",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer.AppRoleAuthResponse = tt.response

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			cp := &ClientParams{
				VaultAddr:       fmt.Sprintf("https://%v/", addr),
				Namespace:       tt.namespace,
				CACertPath:      testRootCert,
				AppRoleID:       "test-approle-id",
				AppRoleSecretID: "test-approle-secret-id",
			}
			cc, err := NewClientConfig(cp, hclog.Default())
			require.NoError(t, err)

			client, reusable, err := cc.NewAuthenticatedClient(APPROLE)
			require.NoError(t, err)
			require.Equal(t, tt.reusable, reusable)

			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestNewAuthenticatedClientCertAuthFailed(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 500

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

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
	require.NoError(t, err)

	_, _, err = cc.NewAuthenticatedClient(CERT)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/cert/login: Error making API request.")
}

func TestNewAuthenticatedClientAppRoleAuthFailed(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.AppRoleAuthResponseCode = 500

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

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
	require.NoError(t, err)

	_, _, err = cc.NewAuthenticatedClient(APPROLE)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/approle/login: Error making API request.")
}

func TestConfigureTLSWithCertAuth(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	require.NoError(t, err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	cert, err := tcc.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)

	testCert, err := testClientCertificatePair()
	require.NoError(t, err)
	require.Equal(t, testCert.Certificate, cert.Certificate)

	testPool, err := testRootCAs()
	require.NoError(t, err)
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects())
}

func TestConfigureTLSWithTokenAuth(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:  "http://example.org:8200",
		CACertPath: testRootCert,
		Token:      "test-token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	require.NoError(t, err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	require.Nil(t, tcc.GetClientCertificate)

	testPool, err := testRootCAs()
	require.NoError(t, err)
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects())
}

func TestConfigureTLSWithAppRoleAuth(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:       "http://example.org:8200",
		CACertPath:      testRootCert,
		AppRoleID:       "test-approle-id",
		AppRoleSecretID: "test-approle-secret",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	require.NoError(t, err)

	tcc := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	require.Nil(t, tcc.GetClientCertificate)

	testPool, err := testRootCAs()
	require.NoError(t, err)
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects())
}

func TestConfigureTLSInvalidCACert(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testInvalidRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.InvalidArgument, "failed to load CA certificate: no PEM blocks")
}

func TestConfigureTLSInvalidClientKey(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		ClientKeyPath:  testInvalidClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.InvalidArgument, "failed to parse client cert and private-key: tls: failed to find any PEM data in key input")
}

func TestConfigureTLSInvalidClientCert(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testInvalidClientCert,
		ClientKeyPath:  testClientKey,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.InvalidArgument, "failed to parse client cert and private-key: open testdata/keys/EC/invalid_client_cert.pem: no such file or directory")
}

func TestConfigureTLSRequireClientCertAndKey(t *testing.T) {
	cp := &ClientParams{
		VaultAddr:      "http://example.org:8200",
		ClientCertPath: testClientCert,
		CACertPath:     testRootCert,
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	vc := vapi.DefaultConfig()
	err = cc.configureTLS(vc)
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "both client cert and client key are required")
}

func TestSignIntermediate(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.SignIntermediateResponseCode = 200
	fakeVaultServer.SignIntermediateResponse = []byte(testSignIntermediateResponse)

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     testRootCert,
		ClientCertPath: testClientCert,
		ClientKeyPath:  testClientKey,
	}

	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	client, _, err := cc.NewAuthenticatedClient(CERT)
	require.NoError(t, err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	resp, err := client.SignIntermediate(testTTL, csr)
	require.NoError(t, err)
	require.NotNil(t, resp.CACertPEM)
	require.NotNil(t, resp.CACertChainPEM)
	require.NotNil(t, resp.CertPEM)
}

func TestSignIntermediateErrorFromEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.SignIntermediateResponseCode = 500
	fakeVaultServer.SignIntermediateResponse = []byte("test error")

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

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
	require.NoError(t, err)

	client, _, err := cc.NewAuthenticatedClient(CERT)
	require.NoError(t, err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	_, err = client.SignIntermediate(testTTL, csr)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to sign intermediate: Error making API request.")
}

func newFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
	fakeVaultServer.ServerCertificatePemPath = testServerCert
	fakeVaultServer.ServerKeyPemPath = testServerKey
	fakeVaultServer.RenewResponseCode = 200
	fakeVaultServer.RenewResponse = []byte(testRenewResponse)
	return fakeVaultServer
}

func testClientCertificatePair() (tls.Certificate, error) {
	cert, err := os.ReadFile(testClientCert)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := os.ReadFile(testClientKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(cert, key)
}

func testRootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(testRootCert)
	if err != nil {
		return nil, err
	}
	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, err
	}
	return pool, nil
}
