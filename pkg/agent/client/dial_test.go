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
// policy application can be tested without dialing.
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

	if err := tlspolicy.ApplyPolicy(tlsConfig, config.TLSPolicy, false); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

func TestServerGRPCClientTLSProfileNotApplied(t *testing.T) {
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
	require.NotEqual(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.Empty(t, tlsConfig.CipherSuites)
	require.Empty(t, tlsConfig.CurvePreferences)
}

func TestServerGRPCClientRequirePQKEM(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)

	tlsConfig, err := serverGRPCClientTLSConfig(ServerClientConfig{
		TrustDomain: td,
		GetBundle: func() []*x509.Certificate {
			return ca.X509Authorities()
		},
		TLSPolicy: tlspolicy.Policy{
			RequirePQKEM: true,
		},
	})
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.Equal(t, []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
	}, tlsConfig.CurvePreferences)
}
