package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/server/datastore"
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
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ds = fakedatastore.New()

	log, _ := test.NewNullLogger()
	ip := net.ParseIP("127.0.0.1")
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(s.ds)

	s.svidState = observer.NewProperty(svid.State{})
	c := &Config{
		GRPCAddr:    &net.TCPAddr{IP: ip, Port: 8000},
		UDSAddr:     &net.UnixAddr{Name: "/tmp/spire-registration.sock", Net: "unix"},
		SVIDStream:  s.svidState.Observe(),
		TrustDomain: td,
		Catalog:     catalog,
		Log:         log,
	}

	s.e = New(c)
}

func (s *EndpointsTestSuite) TestCreateGRPCServer() {
	s.Assert().NotNil(s.e.createGRPCServer(ctx))
}

func (s *EndpointsTestSuite) TestCreateUDSServer() {
	s.Assert().NotNil(s.e.createUDSServer(ctx))
}

func (s *EndpointsTestSuite) TestRegisterNodeAPI() {
	s.Assert().NotPanics(func() { s.e.registerNodeAPI(s.e.createGRPCServer(ctx)) })
}

func (s *EndpointsTestSuite) TestRegisterRegistrationAPI() {
	s.Assert().NotPanics(func() { s.e.registerRegistrationAPI(s.e.createUDSServer(ctx)) })
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

func (s *EndpointsTestSuite) TestGetGRPCServerConfig() {
	certs, pool := s.configureBundle()

	tlsConfig, err := s.e.getGRPCServerConfig(ctx)(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(tls.RequestClientCert, tlsConfig.ClientAuth)
	s.Assert().Equal(certs, tlsConfig.Certificates)
	s.Assert().Equal(pool, tlsConfig.ClientCAs)
}

func (s *EndpointsTestSuite) TestHTTPServerConfig() {
	certs, _ := s.configureBundle()

	tlsConfig, err := s.e.getHTTPServerConfig(ctx)(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(certs, tlsConfig.Certificates)
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
		SVID: &x509.Certificate{Subject: pkix.Name{CommonName: "COMMONNAME"}},
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
		Bundle: &datastore.Bundle{
			TrustDomain: s.e.c.TrustDomain.String(),
			CaCerts:     ca.Raw,
		},
	})
	s.Require().NoError(err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	s.e.svid = svid
	s.e.svidKey = svidKey
	return []tls.Certificate{
		{
			Certificate: [][]byte{svid.Raw, ca.Raw},
			PrivateKey:  svidKey,
		},
	}, caPool
}
