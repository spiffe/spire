package health

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
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

func newCache(log logrus.FieldLogger, clock clock.Clock) *cache {
	return &cache{
		allowedChecks: make(map[string]Checkable),
		currentStatus: make(map[string]checkState),
		log:           log,
		clk:           clock,
	}
}

type cache struct {
	allowedChecks map[string]Checkable

	currentStatus map[string]checkState
	mtx           sync.RWMutex
	clk           clock.Clock

	log   logrus.FieldLogger
	hooks struct {
		statusUpdated chan struct{}
	}
}

func (c *cache) addCheck(name string, checkable Checkable) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if _, ok := c.allowedChecks[name]; ok {
		return fmt.Errorf("check %q has already been added", name)
	}

	c.allowedChecks[name] = checkable
	return nil
}

func (c *cache) getStatuses() map[string]checkState {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	statuses := make(map[string]checkState, len(c.currentStatus))
	for k, v := range c.currentStatus {
		statuses[k] = v
	}

	return statuses
}

func (c *cache) start(ctx context.Context) error {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	if len(c.allowedChecks) < 1 {
		return errors.New("no health checks defined")
	}

	c.startRunner(ctx)
	return nil
}

func (c *cache) startRunner(ctx context.Context) {
	c.log.Debug("Initializing health checkers")
	checkFunc := func() {
		for name, check := range c.allowedChecks {
			state, err := verifyStatus(check)

			checkState := checkState{
				details:   state,
				checkTime: c.clk.Now(),
			}
			if err != nil {
				c.log.WithField("check", name).
					WithError(err).
					Error("Health check has failed")
				checkState.err = err
			}

			c.setStatus(name, checkState)
		}
		if c.hooks.statusUpdated != nil {
			c.hooks.statusUpdated <- struct{}{}
		}
	}

	ticker := c.clk.Ticker(readyCheckInterval)

	go func() {
		defer func() {
			c.log.Debug("Finishing health checker")
			ticker.Stop()
		}()
		for {
			checkFunc()

			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *cache) setStatus(name string, state checkState) {
	c.embellishState(name, &state)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.currentStatus[name] = state
}

func (c *cache) embellishState(name string, state *checkState) {
	// get the previous state
	c.mtx.RLock()
	prevState := c.currentStatus[name]
	c.mtx.RUnlock()

	switch {
	case state.err != nil && prevState.err == nil:
		// State start to fail, add log and set failures tracking
		c.log.WithFields(logrus.Fields{
			"check":   name,
			"details": state.details,
			"error":   state.err.Error(),
		}).Warn("Health check failed")

		state.timeOfFirstFailure = c.clk.Now()
		state.contiguousFailures = 1

	case state.err != nil:
		// Error still happening, carry the time of first failure from the previous state
		state.timeOfFirstFailure = prevState.timeOfFirstFailure
		state.contiguousFailures = prevState.contiguousFailures + 1

	case prevState.err != nil:
		// Current state has no error, notify about error recovering
		failureSeconds := c.clk.Now().Sub(prevState.timeOfFirstFailure).Seconds()
		c.log.WithFields(logrus.Fields{
			"check":    name,
			"details":  state.details,
			"error":    prevState.err.Error(),
			"failures": prevState.contiguousFailures,
			"duration": failureSeconds,
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
