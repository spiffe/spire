package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	observer "github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"google.golang.org/grpc"
)

var (
	ctx = context.Background()
)

func TestEndpoints(t *testing.T) {
	suite.Run(t, new(EndpointsTestSuite))
}

type EndpointsTestSuite struct {
	suite.Suite

	ds *fakedatastore.DataStore

	svidState observer.Property
	e         *endpoints

	mockClock *clock.Mock
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ds = fakedatastore.New()

	log, _ := test.NewNullLogger()
	ip := net.ParseIP("127.0.0.1")
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	s.mockClock = clock.NewMock(s.T())
	s.mockClock.Set(time.Now())

	catalog := fakeservercatalog.New()
	catalog.SetDataStore(s.ds)

	s.svidState = observer.NewProperty(svid.State{})
	c := &Config{
		TCPAddr:     &net.TCPAddr{IP: ip, Port: 8000},
		UDSAddr:     &net.UnixAddr{Name: "/tmp/spire-registration.sock", Net: "unix"},
		SVIDStream:  s.svidState.Observe(),
		TrustDomain: td,
		Catalog:     catalog,
		Log:         log,
	}

	s.e = New(c)
}

func (s *EndpointsTestSuite) TestCreateTCPServer() {
	s.Assert().NotNil(s.e.createTCPServer(ctx))
}

func (s *EndpointsTestSuite) TestCreateUDSServer() {
	s.Assert().NotNil(s.e.createUDSServer(ctx))
}

func (s *EndpointsTestSuite) TestRegisterNodeAPI() {
	s.Assert().NotPanics(func() { s.e.registerNodeAPI(s.e.createTCPServer(ctx)) })
}

func (s *EndpointsTestSuite) TestRegisterRegistrationAPI() {
	s.Assert().NotPanics(func() { s.e.registerRegistrationAPI(s.e.createTCPServer(ctx), s.e.createUDSServer(ctx)) })
}

func (s *EndpointsTestSuite) TestListenAndServe() {
	ctx, cancel := context.WithCancel(ctx)
	errChan := make(chan error)
	go func() { errChan <- s.e.ListenAndServe(ctx) }()

	// It should be stable
	select {
	case err := <-errChan:
		s.T().Errorf("endpoints listener stopped unexpectedly: %v", err)
	case <-time.NewTimer(100 * time.Millisecond).C:
		break
	}

	// It should shutdown cleanly
	cancel()
	select {
	case err := <-errChan:
		s.Assert().NoError(err)
	case <-time.NewTimer(5 * time.Second).C:
		s.T().Errorf("endpoints listener did not shut down")
	}
}

func (s *EndpointsTestSuite) TestGRPCHook() {
	snitchChan := make(chan struct{}, 1)
	hook := func(g *grpc.Server) error {
		snitchChan <- struct{}{}
		return nil
	}
	s.e.c.GRPCHook = hook

	ctx, cancel := context.WithCancel(ctx)
	go s.e.ListenAndServe(ctx)

	select {
	case <-snitchChan:
	case <-time.NewTimer(5 * time.Second).C:
		s.T().Error("grpc hook did not fire")
	}

	cancel()
}

func (s *EndpointsTestSuite) TestGRPCHookFailure() {
	hook := func(_ *grpc.Server) error { return errors.New("i'm an error") }
	s.e.c.GRPCHook = hook

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error, 1)
	go func() { errChan <- s.e.ListenAndServe(ctx) }()

	select {
	case err := <-errChan:
		s.Assert().NotNil(err)
	case <-time.NewTimer(5 * time.Second).C:
		s.Fail("grpc server did not stop after hook failure")
		cancel()
	}
}

func (s *EndpointsTestSuite) TestGetTLSConfig() {
	certs, pool := s.configureBundle()

	tlsConfig, err := s.e.getTLSConfig(ctx)(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth)
	s.Assert().Equal(certs, tlsConfig.Certificates)
	s.Assert().Equal(pool, tlsConfig.ClientCAs)
}

func (s *EndpointsTestSuite) TestSVIDObserver() {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// assert there is no SVID in the current state
	state := s.e.getSVIDState()
	s.Require().Nil(state.SVID)

	go func() {
		s.e.runSVIDObserver(ctx)
	}()

	// update the SVID property
	expectedState := svid.State{
		SVID: []*x509.Certificate{{Subject: pkix.Name{CommonName: "COMMONNAME"}}},
	}
	s.svidState.Update(expectedState)

	// wait until the handler detects the change and updates the SVID
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()
checkLoop:
	for {
		select {
		case <-ticker.C:
			actualState := s.e.getSVIDState()
			if actualState.SVID == nil {
				continue
			}
			s.Require().Equal(expectedState, actualState)
			break checkLoop
		case <-timer.C:
			s.FailNow("timed out waiting for SVID state")
		}
	}
}

// configureBundle sets the bundle in the datastore, and returns the served
// certificates plus an svid in the form of TLS certificate chain and CA pool.
func (s *EndpointsTestSuite) configureBundle() ([]tls.Certificate, *x509.CertPool) {
	svid, svidKey, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	_, err = s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundleutil.BundleProtoFromRootCA(s.e.c.TrustDomain.String(), ca),
	})
	s.Require().NoError(err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	s.e.svid = []*x509.Certificate{svid}
	s.e.svidKey = svidKey
	return []tls.Certificate{
		{
			Certificate: [][]byte{svid.Raw},
			PrivateKey:  svidKey,
		},
	}, caPool
}

func (s *EndpointsTestSuite) TestClientCertificateVerification() {
	caTmpl, err := util.NewCATemplate(s.mockClock, "example.org")
	s.Require().NoError(err)
	caCert, caKey, err := util.SelfSign(caTmpl)
	s.Require().NoError(err)

	serverTmpl, err := util.NewSVIDTemplate(s.mockClock, "spiffe://example.org/server")
	s.Require().NoError(err)
	serverTmpl.DNSNames = []string{"just-for-validation"}
	serverCert, serverKey, err := util.Sign(serverTmpl, caCert, caKey)
	s.Require().NoError(err)

	clientTmpl, err := util.NewSVIDTemplate(s.mockClock, "spiffe://example.org/agent")
	s.Require().NoError(err)
	clientCert, clientKey, err := util.Sign(clientTmpl, caCert, caKey)
	s.Require().NoError(err)

	otherCaTmpl, err := util.NewCATemplate(s.mockClock, "example.org")
	s.Require().NoError(err)
	otherCaCert, otherCaKey, err := util.SelfSign(otherCaTmpl)
	s.Require().NoError(err)

	otherClientTmpl, err := util.NewSVIDTemplate(s.mockClock, "spiffe://example.org/agent")
	s.Require().NoError(err)
	otherClientCert, otherClientKey, err := util.Sign(otherClientTmpl, otherCaCert, otherCaKey)
	s.Require().NoError(err)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	// set the trust bundle and plumb a CA certificate
	_, err = s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://example.org",
			RootCas: []*common.Certificate{
				{DerBytes: caCert.Raw},
			},
		},
	})
	s.Require().NoError(err)
	s.svidState.Update(svid.State{
		SVID: []*x509.Certificate{serverCert},
		Key:  serverKey,
	})

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.e.ListenAndServe(ctx)
	}()

	// This helper function attempts a TLS connection to the gRPC server. It
	// uses the supplied client certificate, if any. It gives up the 2 seconds
	// for the server to start listening, which is generous. Any non-dial
	// related errors (i.e. TLS handshake failures) are returned.
	try := func(cert *tls.Certificate) error {
		tlsConfig := &tls.Config{
			RootCAs: rootCAs,
			// this override is just so we don't have to set up spiffe peer
			// validation of the server by the client, which is outside the
			// scope of this test.
			ServerName: "just-for-validation",
		}
		if cert != nil {
			tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		}
		for i := 0; i < 20; i++ {
			conn, err := tls.Dial("tcp", "127.0.0.1:8000", tlsConfig)
			if err != nil {
				if strings.HasPrefix(err.Error(), "dial") {
					time.Sleep(time.Millisecond * 100)
					continue
				}
				return err
			}
			conn.Close()
			return nil
		}
		s.FailNow("unable to connect to server within 2 seconds")
		return errors.New("unreachable")
	}

	err = try(nil)
	s.Require().NoError(err, "client should be allowed if no cert presented")

	err = try(&tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
	})
	s.Require().NoError(err, "client should be allowed if proper cert presented")

	err = try(&tls.Certificate{
		Certificate: [][]byte{otherClientCert.Raw},
		PrivateKey:  otherClientKey,
	})
	s.Require().Error(err, "client should NOT be allowed if cert presented is not trusted")
}
