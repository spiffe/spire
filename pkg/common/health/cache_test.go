package health

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestAddCheck(t *testing.T) {
	log, _ := test.NewNullLogger()
	t.Run("add check no error", func(t *testing.T) {
		c := newCache(log, clock.NewMock(t))
		err := c.addCheck("foh", &fakeCheckable{})
		require.NoError(t, err)
	})

	t.Run("add duplicated checker", func(t *testing.T) {
		c := newCache(log, clock.NewMock(t))
		err := c.addCheck("foo", &fakeCheckable{})
		require.NoError(t, err)

		err = c.addCheck("bar", &fakeCheckable{})
		require.NoError(t, err)

		err = c.addCheck("foo", &fakeCheckable{})
		require.EqualError(t, err, `check "foo" has already been added`)
	})
}

func TestStartNoCheckerSet(t *testing.T) {
	clockMock := clock.NewMock(t)

	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := newCache(log, clockMock)

	err := c.start(context.Background())
	require.EqualError(t, err, "no health checks defined")
	require.Empty(t, hook.Entries)
}

func TestHealthFailsAndRecover(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	waitFor := make(chan struct{}, 1)
	clockMock := clock.NewMock(t)

	c := newCache(log, clockMock)
	c.hooks.statusUpdated = waitFor

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
			Live:         false,
			Ready:        false,
			LiveDetails:  healthDetails{},
			ReadyDetails: healthDetails{},
		},
	}

	err := c.addCheck("foo", fooChecker)
	require.NoError(t, err)

	err = c.addCheck("bar", barChecker)
	require.NoError(t, err)

	ctx := context.Background()

	err = c.start(ctx)
	require.NoError(t, err)

	t.Run("fail to start initially", func(t *testing.T) {
		// Wait for initial calls
		<-waitFor

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.DebugLevel,
				Message: "Initializing health checkers",
			},
			{
				Level:   logrus.ErrorLevel,
				Message: "Health check has failed",
				Data: logrus.Fields{
					telemetry.Check: "bar",
					telemetry.Error: "subsystem is not live or ready",
				},
			},
			{
				Level:   logrus.WarnLevel,
				Message: "Health check failed",
				Data: logrus.Fields{
					telemetry.Check:   "bar",
					telemetry.Details: "{<nil> false false {} {}}",
					telemetry.Error:   "subsystem is not live or ready",
				},
			},
		}

		expectStatus := map[string]checkState{
			"foo": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
			"bar": {
				details: State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime:          clockMock.Now(),
				err:                errors.New("subsystem is not live or ready"),
				contiguousFailures: 1,
				timeOfFirstFailure: clockMock.Now(),
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
	})

	// Clean logs
	hook.Reset()

	barChecker.state = State{
		Live:         true,
		Ready:        true,
		LiveDetails:  healthDetails{},
		ReadyDetails: healthDetails{},
	}

	t.Run("start successfully after initial failure", func(t *testing.T) {
		// Move to next initial interval
		clockMock.Add(readyCheckInitialInterval)

		// Wait for initial calls
		<-waitFor

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Health check recovered",
				Data: logrus.Fields{
					telemetry.Check:    "bar",
					telemetry.Details:  "{<nil> true true {} {}}",
					telemetry.Duration: "1",
					telemetry.Error:    "subsystem is not live or ready",
					telemetry.Failures: "1",
				},
			},
		}

		expectStatus := map[string]checkState{
			"foo": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
			"bar": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
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

		<-waitFor

		expectStatus := map[string]checkState{
			"foo": {
				details: State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{Err: "live is failing"},
					ReadyDetails: healthDetails{Err: "ready is failing"},
				},
				checkTime:          clockMock.Now(),
				err:                errors.New("subsystem is not live or ready"),
				contiguousFailures: 1,
				timeOfFirstFailure: clockMock.Now(),
			},
			"bar": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "Health check has failed",
				Data: logrus.Fields{
					telemetry.Check: "foo",
					telemetry.Error: "subsystem is not live or ready",
				},
			},
			{
				Level:   logrus.WarnLevel,
				Message: "Health check failed",
				Data: logrus.Fields{
					telemetry.Check:   "foo",
					telemetry.Details: "{<nil> false false {live is failing} {ready is failing}}",
					telemetry.Error:   "subsystem is not live or ready",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
	})

	t.Run("health still failing", func(t *testing.T) {
		hook.Reset()
		previousFailureDate := clockMock.Now()

		// Move to next interval
		clockMock.Add(readyCheckInterval)

		// Wait for new call
		<-waitFor

		expectStatus := map[string]checkState{
			"foo": {
				details: State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{Err: "live is failing"},
					ReadyDetails: healthDetails{Err: "ready is failing"},
				},
				checkTime:          clockMock.Now(),
				err:                errors.New("subsystem is not live or ready"),
				contiguousFailures: 2,
				timeOfFirstFailure: previousFailureDate,
			},
			"bar": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "Health check has failed",
				Data: logrus.Fields{
					telemetry.Check: "foo",
					telemetry.Error: "subsystem is not live or ready",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
	})

	// Health start to recover
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
		<-waitFor

		expectStatus := map[string]checkState{
			"foo": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
			"bar": {
				details: State{
					Live:         true,
					Ready:        true,
					LiveDetails:  healthDetails{},
					ReadyDetails: healthDetails{},
				},
				checkTime: clockMock.Now(),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Health check recovered",
				Data: logrus.Fields{
					telemetry.Check:    "foo",
					telemetry.Details:  "{<nil> true true {} {}}",
					telemetry.Duration: "120",
					telemetry.Error:    "subsystem is not live or ready",
					telemetry.Failures: "2",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
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
