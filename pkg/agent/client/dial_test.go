package client

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

// serverGRPCClientTLSConfig mirrors the TLS setup in NewServerGRPCClient so
// profile application can be tested without dialing.
func serverGRPCClientTLSConfig(config ServerClientConfig) (*tls.Config, error) {
	bundleSource := newBundleSource(config.TrustDomain, config.GetBundle)
	serverID, err := idutil.ServerID(config.TrustDomain)
	if err != nil {
		return nil, err
	}
	authorizer := tlsconfig.AuthorizeID(serverID)

	var tlsConfig *tls.Config
	if config.GetAgentCertificate == nil {
		tlsConfig = tlsconfig.TLSClientConfig(bundleSource, authorizer)
	} else {
		tlsConfig = tlsconfig.MTLSClientConfig(newX509SVIDSource(config.GetAgentCertificate), bundleSource, authorizer)
	}

	if err := tlspolicy.ApplyPolicy(tlsConfig, config.TLSPolicy); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

func TestServerGRPCClientTLSProfile(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)

	tlsConfig, err := serverGRPCClientTLSConfig(ServerClientConfig{
		TrustDomain: td,
		GetBundle: func() []*x509.Certificate {
			return ca.X509Authorities()
		},
		TLSPolicy: tlspolicy.Policy{
			Profile: &tlspolicy.TLSProfile{
				MinTLSVersion: "VersionTLS13",
				CipherSuites: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				},
				CurvePreferences: []string{
					"X25519MLKEM768",
					"secp256r1",
				},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.NotEmpty(t, tlsConfig.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}, tlsConfig.CurvePreferences)
}

func TestServerGRPCClientTLSProfileInvalid(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)

	_, err := serverGRPCClientTLSConfig(ServerClientConfig{
		TrustDomain: td,
		GetBundle: func() []*x509.Certificate {
			return ca.X509Authorities()
		},
		TLSPolicy: tlspolicy.Policy{
			Profile: &tlspolicy.TLSProfile{MinTLSVersion: "VersionTLS99"},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid minTLSVersion")
}
