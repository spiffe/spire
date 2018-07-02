package svid

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
	tomb "gopkg.in/tomb.v2"
)

var (
	ctx = context.Background()
)

func TestRotator(t *testing.T) {
	suite.Run(t, new(RotatorTestSuite))
}

type RotatorTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	ca *mock_ca.MockServerCA

	r *rotator
}

func (s *RotatorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.ca = mock_ca.NewMockServerCA(s.ctrl)

	catalog := fakeservercatalog.New()
	catalog.SetCAs(s.ca)

	log, _ := test.NewNullLogger()
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	c := &RotatorConfig{
		Catalog:     catalog,
		Log:         log,
		TrustDomain: td,
	}

	s.r = NewRotator(c)
}

func (s *RotatorTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *RotatorTestSuite) TestInitialize() {
	cert, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	s.expectSVIDRotation(cert)

	err = s.r.Initialize(ctx)
	s.Require().NoError(err)

	stream := s.r.Subscribe()

	// We should have the latest state
	s.Assert().False(stream.HasNext())

	// Should be equal to the fixture
	state := stream.Value().(State)
	s.Assert().Equal(cert, state.SVID)
}

func (s *RotatorTestSuite) TestRun() {
	// Cert that's valid for 1hr
	temp, err := util.NewSVIDTemplate("spiffe://example.org/test")
	s.Require().NoError(err)
	goodCert, _, err := util.SelfSign(temp)
	s.Require().NoError(err)

	// Cert that's expiring
	temp.NotBefore = time.Now().Add(-1 * time.Hour)
	temp.NotAfter = time.Now()
	badCert, _, err := util.SelfSign(temp)
	s.Require().NoError(err)

	state := State{
		SVID: badCert,
	}
	s.r.state = observer.NewProperty(state)

	s.expectSVIDRotation(goodCert)

	// Fast ticker so the tests complete quickly
	s.r.c.Interval = 10 * time.Millisecond

	stream := s.r.Subscribe()
	s.Require().NoError(s.r.Initialize(ctx))
	ctx, cancel := context.WithCancel(ctx)
	tomb := new(tomb.Tomb)
	tomb.Go(func() error {
		return s.r.Run(ctx)
	})
	defer func() {
		cancel()
		s.Require().NoError(tomb.Wait())
	}()

	select {
	case <-time.NewTimer(5 * time.Second).C:
		s.T().Error("SVID rotation timeout reached")
	case <-stream.Changes():
		state = stream.Next().(State)
		s.Assert().Equal(goodCert, state.SVID)
	}
}

func (s *RotatorTestSuite) TestShouldRotate() {
	// Cert that's valid for 1hr
	temp, err := util.NewSVIDTemplate("spiffe://example.org/test")
	s.Require().NoError(err)
	goodCert, _, err := util.SelfSign(temp)
	s.Require().NoError(err)

	state := State{
		SVID: goodCert,
	}
	s.r.state = observer.NewProperty(state)

	// Cert is brand new
	s.Assert().False(s.r.shouldRotate())

	// Cert that's almost expired
	temp.NotBefore = time.Now().Add(-1 * time.Hour)
	temp.NotAfter = time.Now().Add(1 * time.Minute)
	badCert, _, err := util.SelfSign(temp)
	s.Require().NoError(err)

	state.SVID = badCert
	s.r.state = observer.NewProperty(state)
	s.Assert().True(s.r.shouldRotate())
}

func (s *RotatorTestSuite) TestRotateSVID() {
	cert, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	stream := s.r.Subscribe()
	s.expectSVIDRotation(cert)
	err = s.r.rotateSVID(ctx)
	s.Assert().NoError(err)
	s.Require().True(stream.HasNext())

	state := stream.Next().(State)
	s.Assert().True(cert.Equal(state.SVID))
}

// expectSVIDRotation sets the appropriate expectations for an SVID rotation, and returns
// the the provided certificate to the CA caller
func (s *RotatorTestSuite) expectSVIDRotation(cert *x509.Certificate) {
	signedCert := &ca.SignX509SvidCsrResponse{
		SignedCertificate: cert.Raw,
	}

	s.ca.EXPECT().SignX509SvidCsr(gomock.Any(), gomock.Any()).Return(signedCert, nil)
}
