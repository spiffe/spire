package hashicorpvault

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testRootCert   = "testdata/root-cert.pem"
	testServerCert = "testdata/server-cert.pem"
	testServerKey  = "testdata/server-key.pem"
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

func newFakeVaultServer() *FakeVaultServerConfig {
	fakeVaultServer := NewFakeVaultServerConfig()
	fakeVaultServer.RenewResponseCode = 200
	fakeVaultServer.RenewResponse = []byte(testRenewResponse)
	return fakeVaultServer
}
