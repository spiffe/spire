//go:build !windows

package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/fakes/fakeworkloadapi"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

func TestNewWorkloadAPIListener(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/oidc-discovery-provider"))
	keyDER, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	require.NoError(t, err)

	api := fakeworkloadapi.New(t, &fakeworkloadapi.FakeRequest{
		Req: &workload.X509SVIDRequest{},
		Resp: &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{
			SpiffeId:    svid.ID.String(),
			X509Svid:    x509util.DERFromCertificates(svid.Certificates),
			X509SvidKey: keyDER,
			Bundle:      x509util.DERFromCertificates(ca.X509Authorities()),
		}}},
	})

	tlsPolicy, err := tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{MinTLSVersion: "VersionTLS13"}, nil)
	require.NoError(t, err)

	config := &Config{ServingCertSource: &ServingCertSourceConfig{WorkloadAPI: &ServingCertWorkloadAPIConfig{
		SocketPath: api.Addr().(*net.UnixAddr).Name,
		Addr:       &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}}}

	ctx := t.Context()
	log, _ := test.NewNullLogger()
	listener, err := newWorkloadAPIListener(ctx, log, config, tlsPolicy)
	require.NoError(t, err)
	defer listener.Close()

	// Accept a single connection and complete the TLS handshake on it.
	handshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			handshakeErr <- err
			return
		}
		defer conn.Close()
		handshakeErr <- conn.(*tls.Conn).HandshakeContext(ctx)
	}()

	// The client authenticates the served certificate as the X509-SVID issued
	// by the trust domain, using its bundle.
	dialer := &tls.Dialer{Config: tlsconfig.TLSClientConfig(ca.X509Bundle(), tlsconfig.AuthorizeID(svid.ID))}
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, <-handshakeErr)

	state := conn.(*tls.Conn).ConnectionState()
	require.Equal(t, svid.Certificates[0].Raw, state.PeerCertificates[0].Raw)
	// The TLS policy is applied to the listener.
	require.Equal(t, uint16(tls.VersionTLS13), state.Version)

	// Closing the listener releases the Workload API source.
	require.NoError(t, listener.Close())
	_, err = listener.(*workloadAPIListener).source.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")
}
