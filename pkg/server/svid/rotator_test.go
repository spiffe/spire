package svid

import (
	"context"
	"crypto/x509"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	observer "github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
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

	r        *Rotator
	serverCA *fakeserverca.CA
	logHook  *test.Hook
	clock    *clock.Mock
}

func (s *RotatorTestSuite) SetupTest() {
	td := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	s.clock = clock.NewMock(s.T())
	s.serverCA = fakeserverca.New(s.T(), "example.org", &fakeserverca.Options{
		Clock:       s.clock,
		X509SVIDTTL: testTTL,
	})

	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	s.logHook = hook

	s.r = NewRotator(&RotatorConfig{
		ServerCA:    s.serverCA,
		Log:         log,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: td,
		Clock:       s.clock,
	})
}

func (s *RotatorTestSuite) TestRotationSucceeds() {
	stream := s.r.Subscribe()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.r.Initialize(ctx)
	s.Require().NoError(err)

	// The call to initialize should do the first rotation
	cert := s.requireNewCert(stream, big.NewInt(-1))

	// Run should rotate whenever the certificate is within half of its
	// remaining lifetime.
	wg.Add(1)
	errCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		errCh <- s.r.Run(ctx)
	}()

	s.clock.WaitForTicker(time.Minute, "waiting for the Run() ticker")

	// "expire" the certificate and see that it rotates
	s.clock.Set(certHalfLife(cert))
	s.clock.Add(DefaultRotatorInterval)
	cert = s.requireNewCert(stream, cert.SerialNumber)

	// one more time for good measure.
	s.clock.Set(certHalfLife(cert))
	s.clock.Add(DefaultRotatorInterval)
	cert = s.requireNewCert(stream, cert.SerialNumber)

	// certificate just BARELY before the threshold, so it shouldn't rotate.
	s.clock.Set(certHalfLife(cert).Add(-time.Minute))
	s.clock.Add(DefaultRotatorInterval)
	s.requireStateChangeTimeout(stream)

	cancel()
	s.Require().NoError(<-errCh)
}

func (s *RotatorTestSuite) TestRotationFails() {
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Intentionally change the trust domain to trigger a rotation error
	s.r.c.TrustDomain.Host = "wrong-td.org"

	wg.Add(1)
	errCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		errCh <- s.r.Run(ctx)
	}()

	s.clock.WaitForTicker(time.Minute, "waiting for the Run() ticker")
	s.clock.Add(DefaultRotatorInterval)

	cancel()
	s.Require().NoError(<-errCh)
	spiretest.AssertLogs(s.T(), s.logHook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.DebugLevel,
			Message: "Rotating server SVID",
		},
		{
			Level:   logrus.ErrorLevel,
			Message: "Could not rotate server SVID",
			Data: logrus.Fields{
				logrus.ErrorKey: `"spiffe://wrong-td.org/spire/server" does not belong to trust domain "example.org"`,
			},
		},
		{
			Level:   logrus.DebugLevel,
			Message: "Stopping SVID rotator",
		},
	})
}

func (s *RotatorTestSuite) requireNewCert(stream observer.Stream, prevSerialNumber *big.Int) *x509.Certificate {
	timer := time.NewTimer(time.Second * 10)
	defer timer.Stop()
	select {
	case <-stream.Changes():
		state := stream.Next().(State)
		s.Require().Equal(state, s.r.State())
		s.Require().Len(state.SVID, 1)
		s.Require().NotEqual(0, state.SVID[0].SerialNumber.Cmp(prevSerialNumber))
		return state.SVID[0]
	case <-timer.C:
		s.FailNow("timeout waiting from stream change")
		// unreachable
		return nil
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
