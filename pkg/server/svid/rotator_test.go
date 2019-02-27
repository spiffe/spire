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
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/stretchr/testify/suite"
)

func TestRotator(t *testing.T) {
	suite.Run(t, new(RotatorTestSuite))
}

type RotatorTestSuite struct {
	suite.Suite

	r        *rotator
	serverCA *fakeserverca.ServerCA

	mu  sync.Mutex
	now time.Time
}

func (s *RotatorTestSuite) SetupTest() {
	log, _ := test.NewNullLogger()
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	s.now = time.Now()
	s.serverCA = fakeserverca.New(s.T(), "example.org", &fakeserverca.Options{
		Now: s.nowHook,
	})
	s.r = NewRotator(&RotatorConfig{
		ServerCA:    s.serverCA,
		Log:         log,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: td,
		Interval:    10 * time.Millisecond,
	})
	s.r.hooks.now = s.nowHook
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

	// "expire" the certificate and see that it rotates
	s.advanceTime(time.Second * 30)
	s.requireNewCert(stream, 2)

	// one more time for good measure.
	s.advanceTime(time.Second * 30)
	s.requireNewCert(stream, 3)

	// certificate just BARELY before the threshold, so it shouldn't rotate.
	s.advanceTime(time.Second * 29)
	s.requireStateChangeTimeout(stream)
}

func (s *RotatorTestSuite) nowHook() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *RotatorTestSuite) advanceTime(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

func (s *RotatorTestSuite) requireNewCert(stream observer.Stream, serialNumber int64) {
	timer := time.NewTimer(time.Second)
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
