package svid

import (
	"context"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	observer "github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/stretchr/testify/suite"
)

const (
	testTTL = time.Minute * 10
)

func TestRotator(t *testing.T) {
	suite.Run(t, new(RotatorTestSuite))
}

type RotatorTestSuite struct {
	suite.Suite

	r        *rotator
	serverCA *fakeserverca.ServerCA

	mu    sync.Mutex
	clock *clock.Mock
}

func (s *RotatorTestSuite) SetupTest() {
	log, _ := test.NewNullLogger()
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	s.clock = clock.NewMock(s.T())
	s.serverCA = fakeserverca.New(s.T(), "example.org", &fakeserverca.Options{
		Clock:      s.clock,
		DefaultTTL: testTTL,
	})
	s.r = NewRotator(&RotatorConfig{
		ServerCA:    s.serverCA,
		Log:         log,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: td,
		Clock:       s.clock,
	})
}

func (s *RotatorTestSuite) TestRotation() {
	stream := s.r.Subscribe()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.r.Initialize(ctx)
	s.Require().NoError(err)

	// The call to initialize should do the first rotation
	s.requireNewCert(stream, 1)

	// Run should rotate whenever the certificate is within half of its
	// remaining lifetime.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.r.Run(ctx)
	}()

	s.clock.WaitForTicker(time.Minute, "waiting for the Run() ticker")

	// "expire" the certificate and see that it rotates
	s.clock.Add(testTTL / 2)
	s.clock.Add(DefaultRotatorInterval)
	s.requireNewCert(stream, 2)

	// one more time for good measure.
	s.clock.Add(testTTL / 2)
	s.clock.Add(DefaultRotatorInterval)
	s.requireNewCert(stream, 3)

	// certificate just BARELY before the threshold, so it shouldn't rotate.
	s.clock.Add(testTTL/2 - time.Second)
	s.clock.Add(DefaultRotatorInterval)
	s.requireStateChangeTimeout(stream)
}

func (s *RotatorTestSuite) requireNewCert(stream observer.Stream, serialNumber int64) {
	timer := time.NewTimer(time.Second * 10)
	defer timer.Stop()
	select {
	case <-stream.Changes():
		state := stream.Next().(State)
		s.Require().Len(state.SVID, 2) // SVID and server CA
		s.Require().Equal(0, state.SVID[0].SerialNumber.Cmp(big.NewInt(serialNumber)))
	case <-timer.C:
		s.FailNow("timeout waiting from stream change")
	}
}

func (s *RotatorTestSuite) requireStateChangeTimeout(stream observer.Stream) {
	timer := time.NewTimer(time.Millisecond * 100)
	defer timer.Stop()
	select {
	case <-stream.Changes():
		s.FailNow("expected no state change")
	case <-timer.C:
	}
}
