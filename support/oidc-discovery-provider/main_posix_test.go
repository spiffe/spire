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
	t.Cleanup(func() { _ = listener.Close() })

	// acceptAndHandshake accepts a single connection and completes the TLS
	// handshake on it, reporting the result on the returned channel.
	acceptAndHandshake := func() <-chan error {
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
		return handshakeErr
	}
	clientConfig := func() *tls.Config {
		return tlsconfig.TLSClientConfig(ca.X509Bundle(), tlsconfig.AuthorizeID(svid.ID))
	}

	// The certificate is always taken from the X509Source, so it follows
	// rotation, rather than loaded once.
	conf := listener.(*workloadAPIListener).conf
	require.NotNil(t, conf.GetCertificate)
	require.Empty(t, conf.Certificates)

	// The TLS policy is applied to the listener: a client limited to TLS 1.2
	// is rejected.
	require.Equal(t, uint16(tls.VersionTLS13), conf.MinVersion)
	handshakeErr := acceptAndHandshake()
	tls12Config := clientConfig()
	tls12Config.MaxVersion = tls.VersionTLS12
	_, err = (&tls.Dialer{Config: tls12Config}).DialContext(ctx, "tcp", listener.Addr().String())
	require.Error(t, err)
	require.Error(t, <-handshakeErr)

	// The client authenticates the served certificate as the X509-SVID issued
	// by the trust domain, using its bundle.
	handshakeErr = acceptAndHandshake()
	conn, err := (&tls.Dialer{Config: clientConfig()}).DialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, <-handshakeErr)

	state := conn.(*tls.Conn).ConnectionState()
	require.Equal(t, svid.Certificates[0].Raw, state.PeerCertificates[0].Raw)

	// Closing the listener releases the Workload API source.
	require.NoError(t, listener.Close())
	_, err = listener.(*workloadAPIListener).source.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")
}
