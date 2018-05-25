package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	tomb "gopkg.in/tomb.v2"

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
	ctrl *gomock.Controller

	ca      *mock_ca.MockServerCa
	ds      *mock_datastore.MockDataStore
	catalog *mock_catalog.MockCatalog

	e *endpoints
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.ca = mock_ca.NewMockServerCa(s.ctrl)
	s.ds = mock_datastore.NewMockDataStore(s.ctrl)
	s.catalog = mock_catalog.NewMockCatalog(s.ctrl)

	log, _ := test.NewNullLogger()
	ip := net.ParseIP("127.0.0.1")
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	c := &Config{
		GRPCAddr:    &net.TCPAddr{IP: ip, Port: 8000},
		HTTPAddr:    &net.TCPAddr{IP: ip, Port: 8001},
		SVIDStream:  observer.NewProperty(svid.State{}).Observe(),
		TrustDomain: td,
		Catalog:     s.catalog,
		Log:         log,
	}

	s.e = New(c)
}

func (s *EndpointsTestSuite) TestCreateGRPCServer() {
	s.Assert().NotNil(s.e.createGRPCServer(ctx))
}

func (s *EndpointsTestSuite) TestCreateHTTPServer() {
	s.Assert().NotNil(s.e.createHTTPServer(ctx))
}

func (s *EndpointsTestSuite) TestRegisterNodeAPI() {
	s.Assert().NotPanics(func() { s.e.registerNodeAPI(s.e.createGRPCServer(ctx)) })
}

func (s *EndpointsTestSuite) TestRegisterRegistrationAPI() {
	err := s.e.registerRegistrationAPI(ctx, s.e.createGRPCServer(ctx), s.e.createHTTPServer(ctx))
	s.Assert().Nil(err)
}

func (s *EndpointsTestSuite) TestListenAndServe() {
	// Expectations
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ServerCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any(), gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any(), gomock.Any()).Return(certResp, nil)

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
	// Set all expectations for running gRPC server
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ServerCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any(), gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any(), gomock.Any()).Return(certResp, nil)

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
	case <-time.NewTicker(5 * time.Second).C:
		s.T().Error("grpc hook did not fire")
	}

	cancel()
}

func (s *EndpointsTestSuite) TestGRPCHookFailure() {
	// Set all expectations for running gRPC server
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ServerCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any(), gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any(), gomock.Any()).Return(certResp, nil)

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
	cert, pool := s.expectBundleLookup()

	tlsConfig, err := s.e.getGRPCServerConfig(ctx, nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(tls.RequestClientCert, tlsConfig.ClientAuth)
	s.Assert().Equal(cert, tlsConfig.Certificates)
	s.Assert().Equal(pool, tlsConfig.ClientCAs)
}

func (s *EndpointsTestSuite) TestHTTPServerConfig() {
	cert, _ := s.expectBundleLookup()

	tlsConfig, err := s.e.getGRPCServerConfig(ctx, nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(cert, tlsConfig.Certificates)
}

func (s *EndpointsTestSuite) TestSVIDObserver() {
	state := observer.NewProperty(svid.State{})
	s.e.c.SVIDStream = state.Observe()

	ctx, cancel := context.WithCancel(ctx)
	t := new(tomb.Tomb)
	defer func() {
		cancel()
		s.Require().NoError(t.Wait())
	}()
	t.Go(func() error {
		return s.e.runSVIDObserver(ctx)
	})

	cert, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	svid := svid.State{
		SVID: cert,
		Key:  key,
	}
	state.Update(svid)

	time.Sleep(1 * time.Millisecond)
	s.e.mtx.RLock()
	defer s.e.mtx.RUnlock()
	s.Assert().Equal(cert, s.e.svid)
	s.Assert().Equal(key, s.e.svidKey)
}

// expectBundleLookup sets datastore expectations for CA bundle lookups, and returns the served
// certificates plus an svid in the form of TLS certificate chain and CA pool.
func (s *EndpointsTestSuite) expectBundleLookup() ([]tls.Certificate, *x509.CertPool) {
	svid, svidKey, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	ca, _, err := util.LoadCAFixture()
	require.NoError(s.T(), err)

	dsReq := &datastore.Bundle{TrustDomain: s.e.c.TrustDomain.String()}
	dsResp := &datastore.Bundle{
		TrustDomain: s.e.c.TrustDomain.String(),
		CaCerts:     ca.Raw,
	}
	s.catalog.EXPECT().DataStores().Return([]datastore.DataStore{s.ds})
	s.ds.EXPECT().FetchBundle(gomock.Any(), dsReq).Return(dsResp, nil)

	s.e.svid = svid
	s.e.svidKey = svidKey
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	certChain := [][]byte{svid.Raw, ca.Raw}
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  svidKey,
	}

	return []tls.Certificate{tlsCert}, caPool
}
