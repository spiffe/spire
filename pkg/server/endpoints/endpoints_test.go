package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"google.golang.org/grpc"

	"gopkg.in/tomb.v2"
)

func TestEndpoints(t *testing.T) {
	suite.Run(t, new(EndpointsTestSuite))
}

type EndpointsTestSuite struct {
	suite.Suite
	ctrl *gomock.Controller

	ca      *mock_ca.MockControlPlaneCa
	ds      *mock_datastore.MockDataStore
	catalog *mock_catalog.MockCatalog

	e *endpoints
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.ca = mock_ca.NewMockControlPlaneCa(s.ctrl)
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
		TrustDomain: td,
		Catalog:     s.catalog,
		Log:         log,
	}

	s.e = New(c)
}

func (s *EndpointsTestSuite) TestCreateGRPCServer() {
	s.Assert().NotNil(s.e.createGRPCServer())
}

func (s *EndpointsTestSuite) TestCreateHTTPServer() {
	s.Assert().NotNil(s.e.createHTTPServer())
}

func (s *EndpointsTestSuite) TestRegisterNodeAPI() {
	s.Assert().NotPanics(func() { s.e.registerNodeAPI(s.e.createGRPCServer()) })
}

func (s *EndpointsTestSuite) TestRegisterRegistrationAPI() {
	err := s.e.registerRegistrationAPI(s.e.createGRPCServer(), s.e.createHTTPServer())
	s.Assert().Nil(err)
}

func (s *EndpointsTestSuite) TestRotateSvid() {
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)

	s.expectSVIDRotation(cert)
	s.Assert().NoError(s.e.rotateSVID())
	s.Assert().Equal(cert, s.e.svid)
}

func (s *EndpointsTestSuite) TestStartRotator() {
	s.e.svid = &x509.Certificate{
		NotBefore: time.Now().Add(-10 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}

	// We need a real cert for the rotator to parse
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	s.expectSVIDRotation(cert)

	// Let rotator fire exactly once
	s.e.svidCheck = time.NewTicker(10 * time.Millisecond)
	s.e.t.Go(s.e.startRotator)
	time.Sleep(12 * time.Millisecond)
	s.e.svidCheck.Stop()

	// Make sure the rotator is still alive
	s.Assert().Equal(tomb.ErrStillAlive, s.e.t.Err())

	// Generating the keys and signing the cert take a bit of time. Wait long
	// enough for it to complete - some build systems are slower than others
	time.Sleep(150 * time.Millisecond)

	// Make sure the cert was installed, and take the lock since
	// we might race the update.
	s.e.mtx.Lock()
	s.Assert().True(cert.Equal(s.e.svid))
	s.e.t.Kill(nil)
}

func (s *EndpointsTestSuite) TestListenAndServe() {
	// Expectations
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ControlPlaneCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any()).Return(certResp, nil)

	errChan := make(chan error)
	go func() { errChan <- s.e.ListenAndServe() }()

	// Give the server some time to initialize
	// https://github.com/golang/go/issues/20239
	time.Sleep(100 * time.Millisecond)

	// It should not exit "immediately"
	select {
	case err := <-errChan:
		require.NoError(s.T(), err)
	default:
		break
	}

	// It should shutdown cleanly
	s.e.Shutdown()
	err = <-errChan
	require.NoError(s.T(), err)
}

func (s *EndpointsTestSuite) TestGRPCHook() {
	// Set all expectations for running gRPC server
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ControlPlaneCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any()).Return(certResp, nil)

	// Protect the snitch w/ a mutex to satisfy the race detector
	var snitch bool
	snitchMtx := new(sync.Mutex)
	hook := func(g *grpc.Server) error {
		snitchMtx.Lock()
		defer snitchMtx.Unlock()
		snitch = true
		return nil
	}
	s.e.c.GRPCHook = hook

	errChan := make(chan error)
	go func() { errChan <- s.e.ListenAndServe() }()
	time.Sleep(100 * time.Millisecond)

	snitchMtx.Lock()
	defer snitchMtx.Unlock()
	s.Assert().True(snitch)
	s.e.Shutdown()
	s.Assert().Nil(<-errChan)
}

func (s *EndpointsTestSuite) TestGRPCHookFailure() {
	// Set all expectations for running gRPC server
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	csrResp := &ca.SignCsrResponse{SignedCertificate: cert.Raw}
	certResp := &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}
	s.catalog.EXPECT().CAs().Return([]ca.ControlPlaneCa{s.ca})
	s.ca.EXPECT().SignCsr(gomock.Any()).Return(csrResp, nil)
	s.ca.EXPECT().FetchCertificate(gomock.Any()).Return(certResp, nil)

	hook := func(_ *grpc.Server) error { return errors.New("i'm an error") }
	s.e.c.GRPCHook = hook

	errChan := make(chan error)
	go func() { errChan <- s.e.ListenAndServe() }()
	time.Sleep(100 * time.Millisecond)

	select {
	case err := <-errChan:
		s.Assert().NotNil(err)
	default:
		s.Fail("grpc server still running after hook failure")
		s.e.Shutdown()
		<-errChan
	}
}

func (s *EndpointsTestSuite) TestGetGRPCServerConfig() {
	cert, pool := s.expectBundleLookup()

	tlsConfig, err := s.e.getGRPCServerConfig(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(tls.RequestClientCert, tlsConfig.ClientAuth)
	s.Assert().Equal(cert, tlsConfig.Certificates)
	s.Assert().Equal(pool, tlsConfig.ClientCAs)
}

func (s *EndpointsTestSuite) TestHTTPServerConfig() {
	cert, _ := s.expectBundleLookup()

	tlsConfig, err := s.e.getGRPCServerConfig(nil)
	require.NoError(s.T(), err)

	s.Assert().Equal(cert, tlsConfig.Certificates)
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
	s.ds.EXPECT().FetchBundle(dsReq).Return(dsResp, nil)

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

// expectSVIDRotation sets the appropriate expectations for an SVID rotation, and returns
// the the provided certificate to the CA caller
func (s *EndpointsTestSuite) expectSVIDRotation(cert *x509.Certificate) {
	signedCert := &ca.SignCsrResponse{
		SignedCertificate: cert.Raw,
	}
	caCert := &ca.FetchCertificateResponse{
		StoredIntermediateCert: cert.Raw,
	}

	// TODO: Why is .AnyTimes() required here?
	// TODO: See my commit message
	s.catalog.EXPECT().CAs().Return([]ca.ControlPlaneCa{s.ca}).AnyTimes()
	s.ca.EXPECT().SignCsr(gomock.Any()).Return(signedCert, nil).AnyTimes()
	s.ca.EXPECT().FetchCertificate(gomock.Any()).Return(caCert, nil).AnyTimes()
}
