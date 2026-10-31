package health

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type checkState struct {
	// err is the error returned from a failed health check
	err error

	// details contains more contextual detail about a
	// failing health check.
	details State

	// checkTime is the time of the last health check
	checkTime time.Time

	// contiguousFailures the number of failures that occurred in a row
	contiguousFailures int64

	// timeOfFirstFailure the time of the initial transitional failure for
	// any given health check
	timeOfFirstFailure time.Time
}

type checkerSubsystem struct {
	state     checkState
	checkable Checkable
}

func newCache(log logrus.FieldLogger, clock clock.Clock) *cache {
	return &cache{
		checkerSubsystems: make(map[string]*checkerSubsystem),
		log:               log,
		clk:               clock,
		checkInterval:     readyCheckInterval,
	}
}

type cache struct {
	checkerSubsystems map[string]*checkerSubsystem

	mtx sync.RWMutex
	clk clock.Clock

	checkInterval time.Duration

	log   logrus.FieldLogger
	hooks struct {
		statusUpdated chan struct{}
	}
}

func (c *cache) addCheck(name string, checkable Checkable) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if _, ok := c.checkerSubsystems[name]; ok {
		return fmt.Errorf("check %q has already been added", name)
	}

	c.checkerSubsystems[name] = &checkerSubsystem{
		checkable: checkable,
	}
	return nil
}

func (c *cache) getStatuses() map[string]checkState {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	statuses := make(map[string]checkState, len(c.checkerSubsystems))
	for k, v := range c.checkerSubsystems {
		statuses[k] = v.state
	}

	return statuses
}

func (c *cache) start(ctx context.Context) error {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	if len(c.checkerSubsystems) < 1 {
		return errors.New("no health checks defined")
	}

	c.startRunner(ctx)
	return nil
}

func (c *cache) startRunner(ctx context.Context) {
	c.log.Debug("Initializing health checkers")
	for name, checker := range c.checkerSubsystems {
		go c.runCheck(ctx, name, checker.checkable)
	}
}

// runCheck runs one health check on its own schedule, so that a slow check
// does not delay the others. A failing check is retried sooner so that its
// recovery is detected quickly.
func (c *cache) runCheck(ctx context.Context, name string, checkable Checkable) {
	defer c.log.WithField(telemetry.Check, name).Debug("Finishing health checker")

	var prevState checkState
	var seenStartupError string
	var lastFailureLog time.Time
	for {
		now := c.clk.Now()
		state, err := verifyStatus(checkable)

		checkState := checkState{
			details:   state,
			checkTime: c.clk.Now(),
		}
		if err != nil {
			if state.Started == nil || *state.Started {
				if prevState.err == nil || now.Sub(lastFailureLog) >= failureLogInterval {
					c.log.WithField("check", name).
						WithError(err).
						Error("Health check has failed")
					lastFailureLog = now
				}
			} else if strErr := err.Error(); strErr != seenStartupError {
				c.log.WithField("check", name).
					WithError(err).
					Warn("Health check has failed. Starting up still.")
				seenStartupError = strErr
			}
			checkState.err = err
		}

		prevState = c.setStatus(name, prevState, checkState)
		if c.hooks.statusUpdated != nil {
			c.hooks.statusUpdated <- struct{}{}
		}

		interval := c.checkInterval
		if err != nil {
			interval = readyCheckFailureInterval
		}
		select {
		case <-c.clk.After(interval):
		case <-ctx.Done():
			return
		}
	}
}

func (c *cache) setStatus(name string, prevState checkState, state checkState) checkState {
	c.embellishState(name, &prevState, &state)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// We are sure that checker exists in this place, to be able to check
	// status of a subsystem we must call the checker inside this map
	c.checkerSubsystems[name].state = state
	return state
}

func (c *cache) embellishState(name string, prevState, state *checkState) {
	switch {
	case state.err == nil && prevState.err == nil:
	// All fine continue
	case state.err != nil && prevState.err == nil:
		// State start to fail, add log and set failures tracking
		c.log.WithFields(logrus.Fields{
			telemetry.Check:   name,
			telemetry.Details: state.details,
			telemetry.Error:   state.err.Error(),
		}).Warn("Health check failed")

		state.timeOfFirstFailure = c.clk.Now()
		state.contiguousFailures = 1

	case state.err != nil && prevState.err != nil:
		// Error still happening, carry the time of first failure from the previous state
		state.timeOfFirstFailure = prevState.timeOfFirstFailure
		state.contiguousFailures = prevState.contiguousFailures + 1

	case state.err == nil && prevState.err != nil:
		// Current state has no error, notify about error recovering
		failureSeconds := c.clk.Now().Sub(prevState.timeOfFirstFailure).Seconds()
		c.log.WithFields(logrus.Fields{
			telemetry.Check:    name,
			telemetry.Details:  state.details,
			telemetry.Error:    prevState.err.Error(),
			telemetry.Failures: prevState.contiguousFailures,
			telemetry.Duration: failureSeconds,
		}).Info("Health check recovered")
	}
}

func verifyStatus(check Checkable) (State, error) {
	state := check.CheckHealth()
	var err error
	switch {
	case state.Ready && state.Live:
	case state.Ready && !state.Live:
		err = errors.New("subsystem is not live")
	case !state.Ready && state.Live:
		err = errors.New("subsystem is not ready")
	case !state.Ready && !state.Live:
		err = errors.New("subsystem is not live or ready")
	}
	return state, err
}
