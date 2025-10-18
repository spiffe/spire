package hashicorpvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	vapi "github.com/hashicorp/vault/api"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
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
	testInvalidClientCert = "testdata/invalid-client-cert.pem"
	testClientKey         = "testdata/client-key.pem"
	testInvalidClientKey  = "testdata/invalid-client-key.pem"
)

func TestNewClientConfigWithDefaultValues(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "", // Expect the default value to be used.
		Token:                 "test-token",
		CertAuthMountPoint:    "", // Expect the default value to be used.
		AppRoleAuthMountPoint: "", // Expect the default value to be used.
		K8sAuthMountPoint:     "", // Expect the default value to be used.
		TransitEnginePath:     "", // Expect the default value to be used.
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, defaultPKIMountPoint, cc.clientParams.PKIMountPoint)
	require.Equal(t, defaultCertMountPoint, cc.clientParams.CertAuthMountPoint)
	require.Equal(t, defaultAppRoleMountPoint, cc.clientParams.AppRoleAuthMountPoint)
	require.Equal(t, defaultK8sMountPoint, cc.clientParams.K8sAuthMountPoint)
	require.Equal(t, defaultTransitEnginePath, cc.clientParams.TransitEnginePath)
}

func TestNewClientConfigWithGivenValuesInsteadOfDefaults(t *testing.T) {
	p := &ClientParams{
		VaultAddr:             "http://example.org:8200/",
		PKIMountPoint:         "test-pki",
		Token:                 "test-token",
		CertAuthMountPoint:    "test-tls-cert",
		AppRoleAuthMountPoint: "test-approle",
		K8sAuthMountPoint:     "test-k8s",
		TransitEnginePath:     "test-transit",
	}

	cc, err := NewClientConfig(p, hclog.Default())
	require.NoError(t, err)
	require.Equal(t, "test-pki", cc.clientParams.PKIMountPoint)
	require.Equal(t, "test-tls-cert", cc.clientParams.CertAuthMountPoint)
	require.Equal(t, "test-approle", cc.clientParams.AppRoleAuthMountPoint)
	require.Equal(t, "test-k8s", cc.clientParams.K8sAuthMountPoint)
	require.Equal(t, "test-transit", cc.clientParams.TransitEnginePath)
}

func TestNewAuthenticatedClientTokenAuth(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.LookupSelfResponseCode = 200
	for _, tt := range []struct {
		name            string
		token           string
		response        []byte
		expectRenewable bool
		namespace       string
		expectCode      codes.Code
		expectMsgPrefix string
	}{
		{
			name:            "Token Authentication success / Token never expire",
			token:           "test-token",
			response:        []byte(testLookupSelfResponseNeverExpire),
			expectRenewable: false,
		},
		{
			name:            "Token Authentication success / Token is renewable",
			token:           "test-token",
			response:        []byte(testLookupSelfResponse),
			expectRenewable: true,
		},
		{
			name:            "Token Authentication success / Token is not renewable",
			token:           "test-token",
			response:        []byte(testLookupSelfResponseNotRenewable),
			expectRenewable: false,
		},
		{
			name:            "Token Authentication success / Token is renewable / Namespace is given",
			token:           "test-token",
			response:        []byte(testCertAuthResponse),
			expectRenewable: true,
			namespace:       "test-ns",
		},
		{
			name:            "Token Authentication error / Token is empty",
			token:           "",
			response:        []byte(testCertAuthResponse),
			expectRenewable: true,
			namespace:       "test-ns",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "token is empty",
		},
	} {
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

			client, err := cc.NewAuthenticatedClient(t.Context(), TOKEN)
			if tt.expectMsgPrefix != "" {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
				return
			}

			require.NoError(t, err)

			require.Equal(t, tt.expectRenewable, client.renewable)

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

			client, err := cc.NewAuthenticatedClient(t.Context(), APPROLE)
			require.NoError(t, err)

			require.Equal(t, tt.renew, client.renewable)

			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
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

	_, err = cc.NewAuthenticatedClient(t.Context(), APPROLE)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/approle/login: Error making API request.")
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

			client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
			require.NoError(t, err)

			require.Equal(t, tt.renew, client.renewable)

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

	_, err = cc.NewAuthenticatedClient(t.Context(), CERT)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Unauthenticated, "authentication failed auth/cert/login: Error making API request.")
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

			client, err := cc.NewAuthenticatedClient(t.Context(), K8S)
			require.NoError(t, err)

			require.Equal(t, tt.renew, client.renewable)

			if cp.Namespace != "" {
				headers := client.vaultClient.Headers()
				require.Equal(t, cp.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
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

	_, err = cc.NewAuthenticatedClient(t.Context(), K8S)
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

	_, err = cc.NewAuthenticatedClient(t.Context(), K8S)
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

	client, err := cc.NewAuthenticatedClient(t.Context(), TOKEN)
	require.NoError(t, err)

	client.hooks.renewCh = make(chan error, 1)

	select {
	// TODO: review
	case err := <-client.hooks.renewCh:
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to renew auth token")
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
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects()) //nolint:staticcheck // these pools are not system pools so the use of Subjects() is ok for now
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
	require.Equal(t, testPool.Subjects(), tcc.RootCAs.Subjects()) //nolint:staticcheck // these pools are not system pools so the use of Subjects() is ok for now
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

func TestCreateKey(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.CreateKeyResponseCode = 204

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	err = client.CreateKey(context.Background(), "x509-CA-A", TransitKeyTypeRSA2048)
	require.NoError(t, err)
}

func TestCreateKeyErrorFromEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.CreateKeyResponseCode = 500
	fakeVaultServer.CreateKeyResponse = []byte("test error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	err = client.CreateKey(context.Background(), "x509-CA-A", TransitKeyTypeRSA2048)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to create transit engine key: Error making API request.")
}

func TestGetKeysSingleKey(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeysResponseCode = 200
	fakeVaultServer.GetKeysResponse = []byte(testGetKeysResponseOneKey)
	fakeVaultServer.GetKeyResponseCode = 200
	fakeVaultServer.GetKeyResponse = []byte(testGetKeyResponseP256)

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.GetKeys(context.Background())
	require.NoError(t, err)

	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"))

	require.Len(t, resp, 1)

	require.Equal(t, "x509-CA-A", resp[0].PublicKey.Id)
	require.Equal(t, keymanagerv1.KeyType_EC_P256, resp[0].PublicKey.Type)
	require.Equal(t, block.Bytes, resp[0].PublicKey.PkixData)
	require.Equal(t, "afd4e26c151ce5c1069414bdb08fe5f7a7fdb271d40d077aa1f77a82e8ac5870", resp[0].PublicKey.Fingerprint)
}

func TestGetKeysNoKey(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeysResponseCode = 200
	fakeVaultServer.GetKeysResponse = []byte(testGetKeysResponseNoKeys)

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.GetKeys(context.Background())
	require.NoError(t, err)

	require.Empty(t, resp)
}

func TestGetKeysErrorFromListEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeysResponseCode = 500
	fakeVaultServer.GetKeysResponse = []byte("some error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.GetKeys(context.Background())
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "transit engine list keys call failed: Error making API request.")
	require.Empty(t, resp)
}

func TestGetKeysErrorFromKeyEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeysResponseCode = 200
	fakeVaultServer.GetKeysResponse = []byte(testGetKeysResponseOneKey)
	fakeVaultServer.GetKeyResponseCode = 500
	fakeVaultServer.GetKeyResponse = []byte("some error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.GetKeys(context.Background())
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to get transit engine key: Error making API request.")
	require.Empty(t, resp)
}

func TestGetKey(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeyResponseCode = 200
	fakeVaultServer.GetKeyResponse = []byte(testGetKeyResponseP256)

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.getKey(context.Background(), "x509-CA-A")
	require.NoError(t, err)

	require.Equal(t, map[string]any{
		"name":          "P-256",
		"creation_time": "2024-09-16T18:18:54.284635756Z",
		"public_key":    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n",
	}, resp)
}

func TestGetKeyErrorFromEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeyResponseCode = 500
	fakeVaultServer.GetKeyResponse = []byte("test error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.getKey(context.Background(), "x509-CA-A")
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to get transit engine key: Error making API request.")
	require.Empty(t, resp)
}

func TestGetKeyEntry(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeyResponseCode = 200
	fakeVaultServer.GetKeyResponse = []byte(testGetKeyResponseP256)

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.getKeyEntry(context.Background(), "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A")
	require.NoError(t, err)

	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"))

	require.Equal(t, "x509-CA-A", resp.PublicKey.Id)
	require.Equal(t, keymanagerv1.KeyType_EC_P256, resp.PublicKey.Type)
	require.Equal(t, block.Bytes, resp.PublicKey.PkixData)
	require.Equal(t, "afd4e26c151ce5c1069414bdb08fe5f7a7fdb271d40d077aa1f77a82e8ac5870", resp.PublicKey.Fingerprint)
}

func TestGetKeyEntryErrorFromEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.GetKeyResponseCode = 500
	fakeVaultServer.GetKeyResponse = []byte("some error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.getKeyEntry(context.Background(), "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A")
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to get transit engine key: Error making API request.")
	require.Empty(t, resp)
}

func TestSignData(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.SignDataResponseCode = 200
	fakeVaultServer.SignDataResponse = []byte(testSignDataResponse)

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.SignData(context.Background(), "x509-CA-A", []byte("foo"), TransitHashAlgorithmSHA256, TransitSignatureSignatureAlgorithmPKCS1v15)
	require.NoError(t, err)

	expected, err := base64.StdEncoding.DecodeString("MEQCIHw3maFgxsmzAUsUXnw2ahUgPcomjF8+XxflwH4CsouhAiAYL3RhWx8dP2ymm7hjSUvc9EQ8GPXmLrvgacqkEKQPGw==")
	require.NoError(t, err)
	require.Equal(t, expected, resp)
}

func TestSignDataErrorFromEndpoint(t *testing.T) {
	fakeVaultServer := newFakeVaultServer()
	fakeVaultServer.CertAuthResponseCode = 200
	fakeVaultServer.CertAuthResponse = []byte(testCertAuthResponse)
	fakeVaultServer.SignDataResponseCode = 500
	fakeVaultServer.SignDataResponse = []byte("test error")

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

	client, err := cc.NewAuthenticatedClient(t.Context(), CERT)
	require.NoError(t, err)

	resp, err := client.SignData(context.Background(), "x509-CA-A", []byte("foo"), TransitHashAlgorithmSHA256, TransitSignatureSignatureAlgorithmPKCS1v15)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "transit engine sign call failed: Error making API request.")
	require.Empty(t, resp)
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
