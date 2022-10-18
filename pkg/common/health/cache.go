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

type CheckState struct {
	// Err is the error returned from a failed health check
	Err error

	// Details contains more contextual detail about a
	// failing health check.
	Details State

	// CheckTime is the time of the last health check
	CheckTime time.Time

	// ContiguousFailures the number of failures that occurred in a row
	ContiguousFailures int64

	// TimeOfFirstFailure the time of the initial transitional failure for
	// any given health check
	TimeOfFirstFailure time.Time
}

func NewCache(log logrus.FieldLogger, clock clock.Clock) *Cache {
	return &Cache{
		allowedChecks: make(map[string]Checkable),
		currentStatus: make(map[string]CheckState),
		log:           log,
		clk:           clock,
	}
}

type Cache struct {
	allowedChecks map[string]Checkable

	currentStatus map[string]CheckState
	mutex         sync.Mutex
	clk           clock.Clock

	log logrus.FieldLogger
}

func (c *Cache) AddCheck(name string, checkable Checkable) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.allowedChecks[name]; ok {
		return fmt.Errorf("check %q has already been added", name)
	}

	c.allowedChecks[name] = checkable
	return nil
}

func (c *Cache) Start(ctx context.Context) error {
	if len(c.allowedChecks) < 1 {
		return errors.New("no health checks defined")
	}

	for name, check := range c.allowedChecks {
		c.startRunner(ctx, name, check)
	}
	return nil
}

func (c *Cache) GetStatuses() map[string]CheckState {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.currentStatus
}

func (c *Cache) startRunner(ctx context.Context, name string, check Checkable) {
	log := c.log.WithField("check", name)
	log.Debug("Starting checker")

	checkFunc := func() {
		state, err := verifyStatus(check)

		checkState := CheckState{
			Details:   state,
			CheckTime: c.clk.Now(),
		}
		if err != nil {
			log.WithError(err).Error("healthcheck has failed")
			checkState.Err = err
		}

		c.setStatus(name, checkState)
	}

	ticker := c.clk.Ticker(readyCheckInterval)

	go func() {
		defer func() {
			log.Debug("Checker exiting")
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

func (c *Cache) setStatus(name string, state CheckState) {
	c.embellishState(name, state)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.currentStatus[name] = state
}

func (c *Cache) embellishState(name string, state CheckState) {
	// get the previous state
	c.mutex.Lock()
	prevState := c.currentStatus[name]
	c.mutex.Unlock()

	switch {
	case state.Err != nil && prevState.Err == nil:
		// State start to fail, add log and set failures tracking
		c.log.WithField("check", name).
			WithField("details", state.Details).
			WithField("error", state.Err.Error()).
			Warn("Health check failed")

		state.TimeOfFirstFailure = c.clk.Now()
		state.ContiguousFailures = 1

	case state.Err != nil:
		// Error still happening, carry the time of first failure from the previous state
		state.TimeOfFirstFailure = prevState.TimeOfFirstFailure
		state.ContiguousFailures = prevState.ContiguousFailures + 1

	case prevState.Err != nil:
		// Current state has no error, notify about error recovering
		failureSeconds := c.clk.Now().Sub(prevState.TimeOfFirstFailure).Seconds()
		c.log.WithField("check", name).
			WithField("details", state.Details).
			WithField("error", state.Err.Error()).
			WithField("failures", prevState.ContiguousFailures).
			WithField("duration", failureSeconds).
			Info("Health check recovered")
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
