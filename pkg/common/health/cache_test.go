package health

import (
	"context"
	"errors"
	"testing"
	"time"

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

	require.NoError(t, c.addCheck("foo", fooChecker))
	require.NoError(t, c.addCheck("bar", barChecker))
	require.NoError(t, c.start(context.Background()))

	var firstFailureTime time.Time

	tests := []struct {
		name        string
		setup       func()
		advance     time.Duration
		expectLogs  []spiretest.LogEntry
		expectState func() map[string]checkState
	}{
		{
			name:    "fail to start initially",
			setup:   func() {},
			advance: 0,
			expectLogs: []spiretest.LogEntry{
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
			},
			expectState: func() map[string]checkState {
				return map[string]checkState{
					"foo": {details: fooChecker.state, checkTime: clockMock.Now()},
					"bar": {
						details:            barChecker.state,
						checkTime:          clockMock.Now(),
						err:                errors.New("subsystem is not live or ready"),
						contiguousFailures: 1,
						timeOfFirstFailure: clockMock.Now(),
					},
				}
			},
		},
		{
			name: "start successfully after initial failure",
			setup: func() {
				barChecker.state = State{Live: true, Ready: true}
			},
			advance: readyCheckInitialInterval,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Health check recovered",
					Data: logrus.Fields{
						telemetry.Check:    "bar",
						telemetry.Details:  "{<nil> true true <nil> <nil>}",
						telemetry.Duration: "1",
						telemetry.Error:    "subsystem is not live or ready",
						telemetry.Failures: "1",
					},
				},
			},
			expectState: func() map[string]checkState {
				return map[string]checkState{
					"foo": {details: fooChecker.state, checkTime: clockMock.Now()},
					"bar": {details: barChecker.state, checkTime: clockMock.Now()},
				}
			},
		},
		{
			name: "health start to fail",
			setup: func() {
				fooChecker.state = State{
					Live:         false,
					Ready:        false,
					LiveDetails:  healthDetails{Err: "live is failing"},
					ReadyDetails: healthDetails{Err: "ready is failing"},
				}
			},
			advance: readyCheckInterval,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Health check has failed",
					Data: logrus.Fields{
						telemetry.Check: "foo",
						telemetry.Error: "subsystem is not live or ready"},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Health check failed",
					Data: logrus.Fields{
						telemetry.Check:   "foo",
						telemetry.Details: "{<nil> false false {live is failing} {ready is failing}}",
						telemetry.Error:   "subsystem is not live or ready"}},
			},
			expectState: func() map[string]checkState {
				firstFailureTime = clockMock.Now()
				return map[string]checkState{
					"foo": {
						details:            fooChecker.state,
						checkTime:          firstFailureTime,
						err:                errors.New("subsystem is not live or ready"),
						contiguousFailures: 1,
						timeOfFirstFailure: firstFailureTime,
					},
					"bar": {details: barChecker.state, checkTime: firstFailureTime},
				}
			},
		},
		{
			name:    "health still failing",
			setup:   func() {},
			advance: readyCheckInterval,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Health check has failed",
					Data: logrus.Fields{
						telemetry.Check: "foo",
						telemetry.Error: "subsystem is not live or ready"},
				},
			},
			expectState: func() map[string]checkState {
				return map[string]checkState{
					"foo": {
						details:            fooChecker.state,
						checkTime:          clockMock.Now(),
						err:                errors.New("subsystem is not live or ready"),
						contiguousFailures: 2,
						timeOfFirstFailure: firstFailureTime,
					},
					"bar": {details: barChecker.state, checkTime: clockMock.Now()},
				}
			},
		},
		{
			name: "health recovered",
			setup: func() {
				fooChecker.state = State{Live: true, Ready: true}
			},
			advance: readyCheckInterval,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Health check recovered",
					Data: logrus.Fields{
						telemetry.Check:    "foo",
						telemetry.Details:  "{<nil> true true <nil> <nil>}",
						telemetry.Duration: "120",
						telemetry.Error:    "subsystem is not live or ready",
						telemetry.Failures: "2",
					},
				},
			},
			expectState: func() map[string]checkState {
				return map[string]checkState{
					"foo": {details: fooChecker.state, checkTime: clockMock.Now()},
					"bar": {details: barChecker.state, checkTime: clockMock.Now()},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook.Reset()
			if tt.setup != nil {
				tt.setup()
			}
			if tt.advance > 0 {
				clockMock.Add(tt.advance)
			}
			waitForUpdate(t, waitFor)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
			require.Equal(t, tt.expectState(), c.getStatuses())
		})
	}
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

func waitForUpdate(t *testing.T, ch <-chan struct{}) {
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for health update")
	}
}
