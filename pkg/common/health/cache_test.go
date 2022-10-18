package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestAddCheck(t *testing.T) {
	log, _ := test.NewNullLogger()
	t.Run("add check no error", func(t *testing.T) {
		cache := NewCache(log, clock.New())
		err := cache.AddCheck("foh", &fakeCheckable{})
		require.NoError(t, err)
	})

	t.Run("add duplicated checker", func(t *testing.T) {
		cache := NewCache(log, clock.New())
		err := cache.AddCheck("foo", &fakeCheckable{})
		require.NoError(t, err)

		err = cache.AddCheck("bar", &fakeCheckable{})
		require.NoError(t, err)

		err = cache.AddCheck("foo", &fakeCheckable{})
		require.EqualError(t, err, `check "foo" has already been added`)
	})
}

func TestStartNoCheckerSet(t *testing.T) {
	clockMock := clock.NewMock()

	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	cache := NewCache(log, clockMock)

	err := cache.Start(context.Background())
	require.EqualError(t, err, "no health checks defined")
	require.Empty(t, hook.Entries)
}

func TestHealthFailsAndRecover(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	waitFor := make(chan struct{}, 1)
	clockMock := clock.NewMock()

	cache := NewCache(log, clockMock)
	cache.SetStatusUpdatedHook(waitFor)

	fooChecker := &fakeCheckable{
		state: State{
			Live:         true,
			Ready:        true,
			LiveDetails:  healthDetails{},
			ReadyDetails: healthDetails{},
		},
	}
	barChecker := &fakeCheckable{
		state: State{
			Live:         true,
			Ready:        true,
			LiveDetails:  healthDetails{},
			ReadyDetails: healthDetails{},
		},
	}

	err := cache.AddCheck("foo", fooChecker)
	require.NoError(t, err)

	err = cache.AddCheck("bar", barChecker)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err = cache.Start(ctx)
	require.NoError(t, err)

	t.Run("start successfully", func(t *testing.T) {
		// Wait for initial calls
		select {
		case <-waitFor:
		case <-ctx.Done():
			require.Fail(t, "unable to get updates because context is finished")
		}
		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.DebugLevel,
				Message: "Initializing health checkers",
			},
		}
		expectStatus := map[string]CheckState{
			"foo": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
			"bar": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, cache.GetStatuses())
	})

	// Clean logs
	hook.Reset()

	// Health start to fail
	fooChecker.state = State{
		Live:         false,
		Ready:        false,
		LiveDetails:  healthDetails{Err: "live is failing"},
		ReadyDetails: healthDetails{Err: "ready is failing"},
	}

	t.Run("health start to fail", func(t *testing.T) {
		// Move to next interval
		clockMock.Add(readyCheckInterval)

		// Wait for new call
		select {
		case <-waitFor:
		case <-ctx.Done():
			require.Fail(t, "unable to get updates because context is finished")
		}

		expectStatus := map[string]CheckState{
			"foo": {
				Details: State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{Err: "live is failing"},
					ReadyDetails: healthDetails{Err: "ready is failing"},
				},
				CheckTime:          clockMock.Now(),
				Err:                errors.New("subsystem is not live or ready"),
				ContiguousFailures: 1,
				TimeOfFirstFailure: clockMock.Now(),
			},
			"bar": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "healthcheck has failed",
				Data: logrus.Fields{
					"check": "foo",
					"error": "subsystem is not live or ready",
				},
			},
			{
				Level:   logrus.WarnLevel,
				Message: "Health check failed",
				Data: logrus.Fields{
					"check":   "foo",
					"details": "{false false {live is failing} {ready is failing}}",
					"error":   "subsystem is not live or ready",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, cache.GetStatuses())
	})

	t.Run("health still failing", func(t *testing.T) {
		hook.Reset()
		previousFailureDate := clockMock.Now()

		// Move to next interval
		clockMock.Add(readyCheckInterval)

		// Wait for new call
		select {
		case <-waitFor:
		case <-ctx.Done():
			require.Fail(t, "unable to get updates because context is finished")
		}

		expectStatus := map[string]CheckState{
			"foo": {
				Details: State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{Err: "live is failing"},
					ReadyDetails: healthDetails{Err: "ready is failing"},
				},
				CheckTime:          clockMock.Now(),
				Err:                errors.New("subsystem is not live or ready"),
				ContiguousFailures: 2,
				TimeOfFirstFailure: previousFailureDate,
			},
			"bar": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "healthcheck has failed",
				Data: logrus.Fields{
					"check": "foo",
					"error": "subsystem is not live or ready",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, cache.GetStatuses())
	})

	// Health start to fail
	fooChecker.state = State{
		Live:         true,
		Ready:        true,
		LiveDetails:  healthDetails{},
		ReadyDetails: healthDetails{},
	}

	t.Run("health recovered", func(t *testing.T) {
		hook.Reset()

		// Move to next interval
		clockMock.Add(readyCheckInterval)

		// Wait for new call
		select {
		case <-waitFor:
		case <-ctx.Done():
			require.Fail(t, "unable to get updates because context is finished")
		}

		expectStatus := map[string]CheckState{
			"foo": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
			"bar": {
				Details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				CheckTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Health check recovered",
				Data: logrus.Fields{
					"check":    "foo",
					"details":  "{true true {} {}}",
					"duration": "120",
					"error":    "subsystem is not live or ready",
					"failures": "2",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, cache.GetStatuses())
	})
}

type fakeCheckable struct {
	state State
}

func (f *fakeCheckable) CheckHealth() State {
	return f.state
}

type healthDetails struct {
	Err string `json:"err,omitempty"`
}
