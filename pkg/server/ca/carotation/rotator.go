package carotation

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca/camanage"
	"github.com/zeebo/errs"
)

const (
	backdate       = 10 * time.Second
	rotateInterval = 10 * time.Second
	pruneInterval  = 6 * time.Hour
)

type Config struct {
	Manager       *camanage.Manager
	Log           logrus.FieldLogger
	Clock         clock.Clock
	HealthChecker health.Checker
}

type Rotator struct {
	c Config

	// For keeping track of number of failed rotations.
	failedRotationNum uint64
}

func NewRotator(c Config) *Rotator {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &Rotator{
		c: c,
	}

	_ = c.HealthChecker.AddCheck("server.ca.rotator", &caSyncHealth{m: m})

	return m
}

func (s *Rotator) Initialize(ctx context.Context) error {
	return s.rotate(ctx)
}

func (s *Rotator) Run(ctx context.Context) error {
	if err := s.c.Manager.NotifyBundleLoaded(ctx); err != nil {
		return err
	}
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return s.rotateEvery(ctx, rotateInterval)
		},
		func(ctx context.Context) error {
			return s.pruneBundleEvery(ctx, pruneInterval)
		},
		func(ctx context.Context) error {
			// notifyOnBundleUpdate does not fail but rather logs any errors
			// encountered while notifying
			s.c.Manager.NotifyOnBundleUpdate(ctx)
			return nil
		},
	)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (s *Rotator) rotateEvery(ctx context.Context, interval time.Duration) error {
	ticker := s.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// rotate() errors are logged by rotate() and shouldn't cause the
			// manager run task to bail so ignore them here. The error returned
			// by rotate is used by the unit tests, so we need to keep it for
			// now.
			_ = s.rotate(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Rotator) rotate(ctx context.Context) error {
	x509CAErr := s.rotateX509CA(ctx)
	if x509CAErr != nil {
		atomic.AddUint64(&s.failedRotationNum, 1)
		s.c.Log.WithError(x509CAErr).Error("Unable to rotate X509 CA")
	}

	jwtKeyErr := s.rotateJWTKey(ctx)
	if jwtKeyErr != nil {
		atomic.AddUint64(&s.failedRotationNum, 1)
		s.c.Log.WithError(jwtKeyErr).Error("Unable to rotate JWT key")
	}

	return errs.Combine(x509CAErr, jwtKeyErr)
}

func (s *Rotator) rotateJWTKey(ctx context.Context) error {
	now := s.c.Clock.Now()

	currentJWTKey := s.c.Manager.GetCurrentJWTKeySlot()
	// if there is no current keypair set, generate one
	if currentJWTKey.IsEmpty() {
		if err := s.c.Manager.PrepareJWTKey(ctx); err != nil {
			return err
		}
		s.c.Manager.ActivateJWTKey()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if s.c.Manager.GetNextJWTKeySlot().IsEmpty() && currentJWTKey.ShouldPrepareNext(now) {
		if err := s.c.Manager.PrepareJWTKey(ctx); err != nil {
			return err
		}
	}

	if currentJWTKey.ShouldActivateNext(now) {
		s.c.Manager.RotateJWTKey()
	}

	return nil
}

func (s *Rotator) rotateX509CA(ctx context.Context) error {
	now := s.c.Clock.Now()

	currentX509CA := s.c.Manager.GetCurrentX509CASlot()
	// if there is no current keypair set, generate one
	if currentX509CA.IsEmpty() {
		if err := s.c.Manager.PrepareX509CA(ctx); err != nil {
			return err
		}
		s.c.Manager.ActivateX509CA()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if s.c.Manager.GetNextX509CASlot().IsEmpty() && currentX509CA.ShouldPrepareNext(now) {
		if err := s.c.Manager.PrepareX509CA(ctx); err != nil {
			return err
		}
		// TODO: Review if required
		s.c.Manager.ActivateX509CA()
	}

	if currentX509CA.ShouldActivateNext(now) {
		s.c.Manager.RotateX509CA()
	}

	return nil
}

func (s *Rotator) pruneBundleEvery(ctx context.Context, interval time.Duration) error {
	ticker := s.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.c.Manager.PruneBundle(ctx); err != nil {
				s.c.Log.WithError(err).Error("Could not prune CA certificates")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Rotator) failedRotationResult() uint64 {
	return atomic.LoadUint64(&s.failedRotationNum)
}
