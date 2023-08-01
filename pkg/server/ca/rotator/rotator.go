package rotator

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/zeebo/errs"
)

const (
	rotateInterval = 10 * time.Second
	pruneInterval  = 6 * time.Hour
)

type CAManager interface {
	NotifyBundleLoaded(ctx context.Context) error
	NotifyOnBundleUpdate(ctx context.Context)

	GetCurrentX509CASlot() manager.Slot
	GetNextX509CASlot() manager.Slot

	PrepareX509CA(ctx context.Context) error
	ActivateX509CA()
	RotateX509CA()

	GetCurrentJWTKeySlot() manager.Slot
	GetNextJWTKeySlot() manager.Slot

	PrepareJWTKey(ctx context.Context) error
	ActivateJWTKey()
	RotateJWTKey()

	PruneBundle(ctx context.Context) error
}

type Config struct {
	Manager       CAManager
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

func (r *Rotator) Initialize(ctx context.Context) error {
	return r.rotate(ctx)
}

func (r *Rotator) Run(ctx context.Context) error {
	if err := r.c.Manager.NotifyBundleLoaded(ctx); err != nil {
		return err
	}
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return r.rotateEvery(ctx, rotateInterval)
		},
		func(ctx context.Context) error {
			return r.pruneBundleEvery(ctx, pruneInterval)
		},
		func(ctx context.Context) error {
			// notifyOnBundleUpdate does not fail but rather logs any errors
			// encountered while notifying
			r.c.Manager.NotifyOnBundleUpdate(ctx)
			return nil
		},
	)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (r *Rotator) rotateEvery(ctx context.Context, interval time.Duration) error {
	ticker := r.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// rotate() errors are logged by rotate() and shouldn't cause the
			// manager run task to bail so ignore them here. The error returned
			// by rotate is used by the unit tests, so we need to keep it for
			// now.
			_ = r.rotate(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (r *Rotator) rotate(ctx context.Context) error {
	x509CAErr := r.rotateX509CA(ctx)
	if x509CAErr != nil {
		atomic.AddUint64(&r.failedRotationNum, 1)
		r.c.Log.WithError(x509CAErr).Error("Unable to rotate X509 CA")
	}

	jwtKeyErr := r.rotateJWTKey(ctx)
	if jwtKeyErr != nil {
		atomic.AddUint64(&r.failedRotationNum, 1)
		r.c.Log.WithError(jwtKeyErr).Error("Unable to rotate JWT key")
	}

	return errs.Combine(x509CAErr, jwtKeyErr)
}

func (r *Rotator) rotateJWTKey(ctx context.Context) error {
	now := r.c.Clock.Now()

	currentJWTKey := r.c.Manager.GetCurrentJWTKeySlot()
	// if there is no current keypair set, generate one
	if currentJWTKey.IsEmpty() {
		if err := r.c.Manager.PrepareJWTKey(ctx); err != nil {
			return err
		}
		r.c.Manager.ActivateJWTKey()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if r.c.Manager.GetNextJWTKeySlot().IsEmpty() && currentJWTKey.ShouldPrepareNext(now) {
		if err := r.c.Manager.PrepareJWTKey(ctx); err != nil {
			return err
		}
	}

	if currentJWTKey.ShouldActivateNext(now) {
		r.c.Manager.RotateJWTKey()
	}

	return nil
}

func (r *Rotator) rotateX509CA(ctx context.Context) error {
	now := r.c.Clock.Now()

	currentX509CA := r.c.Manager.GetCurrentX509CASlot()
	// if there is no current keypair set, generate one
	if currentX509CA.IsEmpty() {
		if err := r.c.Manager.PrepareX509CA(ctx); err != nil {
			return err
		}
		r.c.Manager.ActivateX509CA()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if r.c.Manager.GetNextX509CASlot().IsEmpty() && currentX509CA.ShouldPrepareNext(now) {
		if err := r.c.Manager.PrepareX509CA(ctx); err != nil {
			return err
		}
	}

	if currentX509CA.ShouldActivateNext(now) {
		r.c.Manager.RotateX509CA()
	}

	return nil
}

func (r *Rotator) pruneBundleEvery(ctx context.Context, interval time.Duration) error {
	ticker := r.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.c.Manager.PruneBundle(ctx); err != nil {
				r.c.Log.WithError(err).Error("Could not prune CA certificates")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (r *Rotator) failedRotationResult() uint64 {
	return atomic.LoadUint64(&r.failedRotationNum)
}
