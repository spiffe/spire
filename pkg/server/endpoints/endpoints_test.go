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

	"github.com/golang/mock/gomock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
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
	ctrl *gomock.Controller

	ca *mock_ca.MockServerCA
	ds *mock_datastore.MockDataStore

	svidState observer.Property
	e         *endpoints
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.ca = mock_ca.NewMockServerCA(s.ctrl)
	s.ds = mock_datastore.NewMockDataStore(s.ctrl)

	log, _ := test.NewNullLogger()
	ip := net.ParseIP("127.0.0.1")
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	catalog := fakeservercatalog.New()
	catalog.SetCAs(s.ca)
	catalog.SetDataStores(s.ds)

	s.svidState = observer.NewProperty(svid.State{})
	c := &Config{
		GRPCAddr:    &net.TCPAddr{IP: ip, Port: 8000},
		HTTPAddr:    &net.TCPAddr{IP: ip, Port: 8001},
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

	tlsConfig, err := s.e.getGRPCServerConfig(ctx)(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(tls.RequestClientCert, tlsConfig.ClientAuth)
	s.Assert().Equal(cert, tlsConfig.Certificates)
	s.Assert().Equal(pool, tlsConfig.ClientCAs)
}

func (s *EndpointsTestSuite) TestHTTPServerConfig() {
	cert, _ := s.expectBundleLookup()

	tlsConfig, err := s.e.getHTTPServerConfig(ctx)(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(cert, tlsConfig.Certificates)
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
