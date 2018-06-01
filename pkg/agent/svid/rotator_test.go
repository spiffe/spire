package svid

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/test/mock/agent/client"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
)

func TestRotator(t *testing.T) {
	suite.Run(t, new(RotatorTestSuite))
}

type RotatorTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	client *mock_client.MockClient

	bundle observer.Property

	r *rotator
}

func (s *RotatorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.client = mock_client.NewMockClient(s.ctrl)

	b, err := util.LoadBundleFixture()
	s.Require().NoError(err)
	s.bundle = observer.NewProperty(b)

	log, _ := test.NewNullLogger()
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}
	c := &RotatorConfig{
		Log:          log,
		TrustDomain:  td,
		SpiffeID:     "spiffe://example.org/spire/agent/1234",
		BundleStream: s.bundle.Observe(),
	}
	s.r, _ = NewRotator(c)
	s.r.client = s.client
}

func (s *RotatorTestSuite) TeardownTest() {
	s.ctrl.Finish()
}

func (s *RotatorTestSuite) TestStart() {
	cert, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	s.expectSVIDRotation(cert)

	state := State{
		SVID: cert,
		Key:  key,
	}
	s.r.state = observer.NewProperty(state)

	s.r.Start()

	stream := s.r.Subscribe()

	// We should have the latest state
	s.Assert().False(stream.HasNext())

	// Should be equal to the fixture
	state = stream.Value().(State)
	s.Assert().Equal(cert, state.SVID)
	s.Assert().Equal(key, state.Key)

	s.r.Stop()
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
	go s.r.run()
	select {
	case <-time.NewTicker(5 * time.Second).C:
		s.T().Error("SVID rotation timeout reached")
	case <-stream.Changes():
		state = stream.Next().(State)
		s.Assert().Equal(goodCert, state.SVID)
	}

	s.r.Stop()
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
	err = s.r.rotateSVID()
	s.Assert().NoError(err)
	s.Require().True(stream.HasNext())

	state := stream.Next().(State)
	s.Assert().True(cert.Equal(state.SVID))
}

// expectSVIDRotation sets the appropriate expectations for an SVID rotation, and returns
// the the provided certificate to the client.Client caller.
func (s *RotatorTestSuite) expectSVIDRotation(cert *x509.Certificate) {
	s.client.EXPECT().
		FetchUpdates(gomock.Any()).
		Return(&client.Update{
			SVIDs: map[string]*node.Svid{
				s.r.c.SpiffeID: {
					SvidCert: cert.Raw,
				},
			},
		}, nil)
	s.client.EXPECT().Release().MaxTimes(2)
}
