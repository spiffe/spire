package vault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testRootCert          = "testdata/root-cert.pem"
	testInvalidRootCert   = "testdata/invalid-root-cert.pem"
	testServerCert        = "testdata/server-cert.pem"
	testServerKey         = "testdata/server-key.pem"
	testClientCert        = "testdata/client-cert.pem"
	testClientKey         = "testdata/client-key.pem"
	testInvalidClientCert = "testdata/invalid-client-cert.pem"
	testInvalidClientKey  = "testdata/invalid-client-key.pem"
	testReqCSR            = "testdata/intermediate-csr.pem"
)

func TestNewClientConfigWithDefaultValues(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "", // Expect the default value to be used.
		Token:                 "test-token",
		CertAuthMountPoint:    "", // Expect the default value to be used.
		AppRoleAuthMountPoint: "", // Expect the default value to be used.
		K8sAuthMountPoint:     "", // Expect the default value to be used.
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, defaultPKIMountPoint, cc.clientParams.PKIMountPoint)
	require.Equal(t, defaultCertMountPoint, cc.clientParams.CertAuthMountPoint)
	require.Equal(t, defaultAppRoleMountPoint, cc.clientParams.AppRoleAuthMountPoint)
	require.Equal(t, defaultK8sMountPoint, cc.clientParams.K8sAuthMountPoint)
}

func TestNewClientConfigWithGivenValuesInsteadOfDefaults(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "test-pki",
		Token:                 "test-token",
		CertAuthMountPoint:    "test-tls-cert",
		AppRoleAuthMountPoint: "test-approle",
		K8sAuthMountPoint:     "test-k8s",
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, "test-pki", cc.clientParams.PKIMountPoint)
	require.Equal(t, "test-tls-cert", cc.clientParams.CertAuthMountPoint)
	require.Equal(t, "test-approle", cc.clientParams.AppRoleAuthMountPoint)
	require.Equal(t, "test-k8s", cc.clientParams.K8sAuthMountPoint)
}

func TestNewAuthenticatedClientCertAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	for _, tt := range []struct {
		name      string
		response  []byte
		renew     bool
		namespace string
	}{
		{
			name:     "Cert Authentication success / Token is renewable",
			response: []byte(testCertAuthResponse),
			renew:    true,
		},
		{
			name:     "Cert Authentication success / Token is not renewable",
			response: []byte(testCertAuthResponseNotRenewable),
		},
		{
			name:      "Cert Authentication success / Token is renewable / Namespace is given",
			response:  []byte(testCertAuthResponse),
			renew:     true,
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

			renewCh := make(chan struct{})
			client, err := cc.NewAuthenticatedClient(CERT, renewCh)
			require.NoError(t, err)

			select {
			case <-renewCh:
				require.Equal(t, false, tt.renew)
			default:
				require.Equal(t, true, tt.renew)
			}

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
		renew           bool
		namespace       string
		expectCode      codes.Code
		expectMsgPrefix string
	}{
		{
			name:     "Token Authentication success / Token never expire",
			token:    "test-token",
			response: []byte(testLookupSelfResponseNeverExpire),
			renew:    true,
		},
		{
			name:     "Token Authentication success / Token is renewable",
			token:    "test-token",
			response: []byte(testLookupSelfResponse),
			renew:    true,
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
			renew:     true,
			namespace: "test-ns",
		},
		{
			name:            "Token Authentication error / Token is empty",
			token:           "",
			response:        []byte(testCertAuthResponse),
			renew:           true,
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

			renewCh := make(chan struct{})
			client, err := cc.NewAuthenticatedClient(TOKEN, renewCh)
			if tt.expectMsgPrefix != "" {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
				return
			}

			require.NoError(t, err)

			select {
			case <-renewCh:
				require.Equal(t, false, tt.renew)
			default:
				require.Equal(t, true, tt.renew)
			}

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
		renew     bool
		namespace string
	}{
		{
			name:     "AppRole Authentication success / Token is renewable",
			response: []byte(testAppRoleAuthResponse),
			renew:    true,
		},
		{
			name:     "AppRole Authentication success / Token is not renewable",
			response: []byte(testAppRoleAuthResponseNotRenewable),
		},
		{
			name:      "AppRole Authentication success / Token is renewable / Namespace is given",
			response:  []byte(testAppRoleAuthResponse),
			renew:     true,
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

			renewCh := make(chan struct{})
			client, err := cc.NewAuthenticatedClient(APPROLE, renewCh)
			require.NoError(t, err)

			select {
			case <-renewCh:
				require.Equal(t, false, tt.renew)
			default:
				require.Equal(t, true, tt.renew)
			}

			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestNewAuthenticatedClientK8sAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.K8sAuthResponseCode = 200
	for _, tt := range []struct {
		name      string
		response  []byte
		renew     bool
		namespace string
	}{
		{
			name:     "K8s Authentication success / Token is renewable",
			response: []byte(testK8sAuthResponse),
			renew:    true,
		},
		{
			name:     "K8s Authentication success / Token is not renewable",
			response: []byte(testK8sAuthResponseNotRenewable),
		},
		{
			name:      "K8s Authentication success / Token is renewable / Namespace is given",
			response:  []byte(testK8sAuthResponse),
			renew:     true,
			namespace: "test-ns",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeVaultServer.K8sAuthResponse = tt.response

			s, addr, err := fakeVaultServer.NewTLSServer()
			require.NoError(t, err)

			s.Start()
			defer s.Close()

			cp := &ClientParams{
				VaultAddr:        fmt.Sprintf("https://%v/", addr),
				Namespace:        tt.namespace,
				CACertPath:       testRootCert,
				K8sAuthRoleName:  "my-role",
				K8sAuthTokenPath: "testdata/k8s/token",
			}
			cc, err := NewClientConfig(cp, hclog.Default())
			require.NoError(t, err)

			renewCh := make(chan struct{})
			client, err := cc.NewAuthenticatedClient(K8S, renewCh)
			require.NoError(t, err)

			select {
			case <-renewCh:
				require.Equal(t, false, tt.renew)
			default:
				require.Equal(t, true, tt.renew)
			}

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

	renewCh := make(chan struct{})
	_, err = cc.NewAuthenticatedClient(CERT, renewCh)
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

	renewCh := make(chan struct{})
	_, err = cc.NewAuthenticatedClient(APPROLE, renewCh)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/approle/login: Error making API request.")
}

func TestNewAuthenticatedClientK8sAuthFailed(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.K8sAuthResponseCode = 500

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	retry := 0 // Disable retry
	cp := &ClientParams{
		MaxRetries:       &retry,
		VaultAddr:        fmt.Sprintf("https://%v/", addr),
		CACertPath:       testRootCert,
		K8sAuthRoleName:  "my-role",
		K8sAuthTokenPath: "testdata/k8s/token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	renewCh := make(chan struct{})
	_, err = cc.NewAuthenticatedClient(K8S, renewCh)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/kubernetes/login: Error making API request.")
}

func TestNewAuthenticatedClientK8sAuthInvalidPath(t *testing.T) {
	retry := 0 // Disable retry
	cp := &ClientParams{
		MaxRetries:       &retry,
		VaultAddr:        "https://example.org:8200",
		CACertPath:       testRootCert,
		K8sAuthTokenPath: "invalid/k8s/token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	renewCh := make(chan struct{})
	_, err = cc.NewAuthenticatedClient(K8S, renewCh)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to read k8s service account token:")
}

func TestRenewTokenFailed(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.LookupSelfResponse = []byte(testLookupSelfResponseShortTTL)
	fakeVaultServer.LookupSelfResponseCode = 200
	fakeVaultServer.RenewResponse = []byte("fake renew error")
	fakeVaultServer.RenewResponseCode = 500

	s, addr, err := fakeVaultServer.NewTLSServer()
	require.NoError(t, err)

	s.Start()
	defer s.Close()

	retry := 0
	cp := &ClientParams{
		MaxRetries: &retry,
		VaultAddr:  fmt.Sprintf("https://%v/", addr),
		CACertPath: testRootCert,
		Token:      "test-token",
	}
	cc, err := NewClientConfig(cp, hclog.Default())
	require.NoError(t, err)

	renewCh := make(chan struct{})
	_, err = cc.NewAuthenticatedClient(TOKEN, renewCh)
	require.NoError(t, err)

	select {
	case <-renewCh:
	case <-time.After(1 * time.Second):
		t.Error("renewChan did not close in the expected time")
	}
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
	require.True(t, testPool.Equal(tcc.RootCAs))
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
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects()) // nolint // these pools are not system pools so the use of Subjects() is ok for now
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
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects()) // nolint // these pools are not system pools so the use of Subjects() is ok for now
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
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.InvalidArgument, "failed to parse client cert and private-key: tls: failed to find any PEM data in certificate input")
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

	renewCh := make(chan struct{})
	client, err := cc.NewAuthenticatedClient(CERT, renewCh)
	require.NoError(t, err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	resp, err := client.SignIntermediate(testTTL, csr)
	require.NoError(t, err)
	require.NotNil(t, resp.UpstreamCACertPEM)
	require.NotNil(t, resp.UpstreamCACertChainPEM)
	require.NotNil(t, resp.CACertPEM)
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

	renewCh := make(chan struct{})
	client, err := cc.NewAuthenticatedClient(CERT, renewCh)
	require.NoError(t, err)

	testTTL := "0"
	csr, err := pemutil.LoadCertificateRequest(testReqCSR)
	require.NoError(t, err)

	_, err = client.SignIntermediate(testTTL, csr)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to sign intermediate: Error making API request.")
}

func newFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
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
