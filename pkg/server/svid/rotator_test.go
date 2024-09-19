package svid

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	observer "github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testTTL = time.Minute * 10
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestRotator(t *testing.T) {
	suite.Run(t, new(RotatorTestSuite))
}

type RotatorTestSuite struct {
	suite.Suite

	serverCA *fakeserverca.CA
	r        *Rotator
	logHook  *test.Hook
	clock    *clock.Mock
}

func (s *RotatorTestSuite) SetupTest() {
	s.clock = clock.NewMock(s.T())
	s.serverCA = fakeserverca.New(s.T(), trustDomain, &fakeserverca.Options{
		Clock:       s.clock,
		X509SVIDTTL: testTTL,
	})

	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	s.logHook = hook

	s.r = NewRotator(&RotatorConfig{
		ServerCA: s.serverCA,
		Log:      log,
		Metrics:  telemetry.Blackhole{},
		Clock:    s.clock,
		KeyType:  keymanager.ECP256,
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

func (s *RotatorTestSuite) TestForceRotation() {
	stream := s.r.Subscribe()
	t := s.T()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	err := s.r.Initialize(ctx)
	s.Require().NoError(err)

	originalCA := s.serverCA.Bundle()

	// New CA
	signer := testkey.MustEC256()
	template, err := s.serverCA.CredBuilder().BuildSelfSignedX509CATemplate(context.Background(), credtemplate.SelfSignedX509CAParams{
		PublicKey: signer.Public(),
	})
	require.NoError(t, err)

	newCA, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	require.NoError(t, err)

	newCASubjectID := newCA.SubjectKeyId

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

	// Change X509CA
	s.serverCA.SetX509CA(&ca.X509CA{
		Signer:      signer,
		Certificate: newCA,
	})

	s.clock.WaitForTicker(time.Minute, "waiting for the Run() ticker")

	s.r.taintedReceived = make(chan bool, 1)
	// Notify that old authority is tainted
	s.serverCA.NotifyTaintedX509Authorities(originalCA)

	select {
	case received := <-s.r.taintedReceived:
		assert.True(t, received)
	case <-ctx.Done():
		s.Fail("no notification received")
	}

	// Advance interval, so new SVID is signed
	s.clock.Add(DefaultRotatorInterval)
	cert = s.requireNewCert(stream, cert.SerialNumber)
	require.Equal(t, newCASubjectID, cert.AuthorityKeyId)

	// Notify again, must not mark as tainted
	s.serverCA.NotifyTaintedX509Authorities(originalCA)
	s.clock.Add(DefaultRotatorInterval)
	s.requireStateChangeTimeout(stream)
	require.False(t, s.r.isSVIDTainted)

	cancel()
	s.Require().NoError(<-errCh)
}

func (s *RotatorTestSuite) TestRotationFails() {
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Inject an error into the rotation flow.
	s.serverCA.SetError(errors.New("oh no"))

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
				logrus.ErrorKey: "oh no",
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
