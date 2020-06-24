package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
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

	svidState svid.State
	e         *Endpoints

	mockClock *clock.Mock
}

func (s *EndpointsTestSuite) SetupTest() {
	s.ds = fakedatastore.New(s.T())

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

	s.svidState = svid.State{}
	c := &Config{
		TCPAddr: &net.TCPAddr{IP: ip, Port: 8000},
		UDSAddr: &net.UnixAddr{Name: "/tmp/spire-registration.sock", Net: "unix"},
		SVIDObserver: svid.ObserverFunc(func() svid.State {
			return s.svidState
		}),
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
	s.Assert().NotNil(s.e.createUDSServer())
}

func (s *EndpointsTestSuite) TestRegisterNodeAPI() {
	s.Require().NoError(s.e.registerNodeAPI(s.e.createTCPServer(ctx)))
}

func (s *EndpointsTestSuite) TestRegisterRegistrationAPI() {
	s.Assert().NotPanics(func() { s.e.registerRegistrationAPI(s.e.createTCPServer(ctx), s.e.createUDSServer()) })
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
	go func() { _ = s.e.ListenAndServe(ctx) }()

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
	s.Assert().EqualValues(tls.VersionTLS12, tlsConfig.MinVersion)
}

// configureBundle sets the bundle in the datastore, and returns the served
// certificates plus an svid in the form of TLS certificate chain and CA pool.
func (s *EndpointsTestSuite) configureBundle() ([]tls.Certificate, *x509.CertPool) {
	cert, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	_, err = s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundleutil.BundleProtoFromRootCA(s.e.c.TrustDomain.String(), ca),
	})
	s.Require().NoError(err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	s.svidState = svid.State{
		SVID: []*x509.Certificate{cert},
		Key:  key,
	}

	return []tls.Certificate{
		{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
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
	s.svidState = svid.State{
		SVID: []*x509.Certificate{serverCert},
		Key:  serverKey,
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.e.ListenAndServe(ctx)
	}()

	// This helper function attempts a TLS connection to the gRPC server. It
	// uses the supplied client certificate, if any. It gives up the 2 seconds
	// for the server to start listening, which is generous. Any non-dial
	// related errors (i.e. TLS handshake failures) are returned.
	try := func(cert *tls.Certificate, maxVersion uint16) error {
		tlsConfig := &tls.Config{
			RootCAs: rootCAs,
			// this override is just so we don't have to set up spiffe peer
			// validation of the server by the client, which is outside the
			// scope of this test.
			ServerName: "just-for-validation",
			MaxVersion: maxVersion,
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
			// Need to receive a single byte to complete the TLS 1.3 handshake
			// which was supported in Go1.12 but now default in go1.13 (see
			// https://golang.org/doc/go1.12#tls_1_3)
			b := make([]byte, 1)
			if _, err := conn.Read(b); err != nil {
				return err
			}
			conn.Close()
			return nil
		}
		s.FailNow("unable to connect to server within 2 seconds")
		return errors.New("unreachable")
	}

	for _, test := range []struct {
		msg        string
		expectErr  bool
		cert       tls.Certificate
		maxVersion uint16
	}{
		{
			msg: "client should be allowed if no cert presented",
		},
		{
			msg: "client should be allowed if proper cert presented",
			cert: tls.Certificate{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  clientKey,
			},
		},
		{
			msg:       "client should NOT be allowed if cert presented is not trusted",
			expectErr: true,
			cert: tls.Certificate{
				Certificate: [][]byte{otherClientCert.Raw},
				PrivateKey:  otherClientKey,
			},
		},
		{
			msg:        "TLS version 1.1 should be rejected",
			expectErr:  true,
			maxVersion: tls.VersionTLS11,
		},
		{
			msg:        "TLS version 1.0 should be rejected",
			expectErr:  true,
			maxVersion: tls.VersionTLS10,
		},
	} {
		err := try(&test.cert, test.maxVersion)
		if test.expectErr {
			s.Require().Error(err, test.msg)
		} else {
			s.Require().NoError(err, test.msg)
		}
	}
}
