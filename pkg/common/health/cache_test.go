package health

import (
	"context"
	"errors"
	"slices"
	"sync"
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
	clockMock := clock.NewMock(t)

	c := newCache(log, clockMock)
	runs := watchRuns(t, c, clockMock)

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
		runs.wait(2)

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
		initialCheckTime := clockMock.Now()
		// Move to next failure interval
		clockMock.Add(readyCheckFailureInterval)

		// Wait for initial calls
		runs.wait(1)

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
				checkTime: initialCheckTime,
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
		// Move to when foo is due, a second before bar
		clockMock.Add(readyCheckInterval - readyCheckFailureInterval)

		runs.wait(1)

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
				checkTime: clockMock.Now().Add(-(readyCheckInterval - readyCheckFailureInterval)),
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
		clockMock.Add(readyCheckFailureInterval)

		// Wait for new call
		runs.wait(2)

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

		spiretest.AssertLogs(t, hook.AllEntries(), nil)
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
		clockMock.Add(readyCheckFailureInterval)

		// Wait for new call
		runs.wait(1)

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
				checkTime: clockMock.Now().Add(-readyCheckFailureInterval),
			},
		}

		expectLogs := []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Health check recovered",
				Data: logrus.Fields{
					telemetry.Check:    "foo",
					telemetry.Details:  "{<nil> true true {} {}}",
					telemetry.Duration: "2",
					telemetry.Error:    "subsystem is not live or ready",
					telemetry.Failures: "2",
				},
			},
		}

		spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
		require.Equal(t, expectStatus, c.getStatuses())
	})
}

func TestOnlyFailingCheckIsRetriedSooner(t *testing.T) {
	log, _ := test.NewNullLogger()
	clockMock := clock.NewMock(t)

	c := newCache(log, clockMock)
	c.checkInterval = 10 * time.Second
	runs := watchRuns(t, c, clockMock)

	healthy := &countingCheckable{state: State{Live: true, Ready: true}}
	flaky := &countingCheckable{state: State{Live: true, Ready: true}}
	require.NoError(t, c.addCheck("healthy", healthy))
	require.NoError(t, c.addCheck("flaky", flaky))
	require.NoError(t, c.start(context.Background()))

	require.Equal(t, []time.Duration{10 * time.Second, 10 * time.Second}, runs.wait(2))

	flaky.setState(State{})
	clockMock.Add(10 * time.Second)
	require.Equal(t, []time.Duration{readyCheckFailureInterval, 10 * time.Second}, runs.wait(2))
	require.Equal(t, 2, healthy.count())
	require.Equal(t, 2, flaky.count())

	clockMock.Add(readyCheckFailureInterval)
	require.Equal(t, []time.Duration{readyCheckFailureInterval}, runs.wait(1))
	require.Equal(t, 2, healthy.count())
	require.Equal(t, 3, flaky.count())

	flaky.setState(State{Live: true, Ready: true})
	clockMock.Add(readyCheckFailureInterval)
	require.Equal(t, []time.Duration{10 * time.Second}, runs.wait(1))
	require.Equal(t, 2, healthy.count())
	require.Equal(t, 4, flaky.count())

	clockMock.Add(8 * time.Second)
	require.Equal(t, []time.Duration{10 * time.Second}, runs.wait(1))
	require.Equal(t, 3, healthy.count())
	require.Equal(t, 4, flaky.count())
}

func TestSlowCheckDoesNotDelayOthers(t *testing.T) {
	log, _ := test.NewNullLogger()
	clockMock := clock.NewMock(t)

	c := newCache(log, clockMock)
	runs := watchRuns(t, c, clockMock)

	slow := &blockingCheckable{release: make(chan struct{})}
	t.Cleanup(func() { close(slow.release) })
	fast := &countingCheckable{state: State{Live: true, Ready: true}}
	require.NoError(t, c.addCheck("slow", slow))
	require.NoError(t, c.addCheck("fast", fast))
	require.NoError(t, c.start(context.Background()))

	runs.wait(1)
	require.Equal(t, 1, fast.count())

	clockMock.Add(readyCheckInterval)
	runs.wait(1)
	require.Equal(t, 2, fast.count())
}

func TestFailingCheckIsLoggedOncePerMinute(t *testing.T) {
	log, hook := test.NewNullLogger()
	clockMock := clock.NewMock(t)

	c := newCache(log, clockMock)
	runs := watchRuns(t, c, clockMock)

	failing := &countingCheckable{state: State{}}
	require.NoError(t, c.addCheck("failing", failing))
	require.NoError(t, c.start(context.Background()))

	failedLogs := func() int {
		count := 0
		for _, entry := range hook.AllEntries() {
			if entry.Message == "Health check has failed" {
				count++
			}
		}
		return count
	}

	runs.wait(1)
	require.Equal(t, 1, failedLogs())

	for range 59 {
		clockMock.Add(readyCheckFailureInterval)
		runs.wait(1)
	}
	require.Equal(t, 60, failing.count())
	require.Equal(t, 1, failedLogs())

	clockMock.Add(readyCheckFailureInterval)
	runs.wait(1)
	require.Equal(t, 2, failedLogs())
}

// checkRuns follows the checks a cache runs, each on its own goroutine.
type checkRuns struct {
	t       *testing.T
	updated chan struct{}
	waits   chan time.Duration
}

func watchRuns(t *testing.T, c *cache, clockMock *clock.Mock) *checkRuns {
	r := &checkRuns{
		t:       t,
		updated: make(chan struct{}, 10),
		waits:   make(chan time.Duration, 10),
	}
	c.hooks.statusUpdated = r.updated
	clockMock.SetAfterHook(func(d time.Duration) <-chan time.Time {
		ch := clockMock.Mock.After(d)
		r.waits <- d
		return ch
	})
	return r
}

// wait waits until n checks have run and are waiting for their next run, and
// returns how long each of them waits, shortest first.
func (r *checkRuns) wait(n int) []time.Duration {
	r.t.Helper()
	waits := make([]time.Duration, 0, n)
	for range n {
		select {
		case <-r.updated:
		case <-time.After(3 * time.Second):
			r.t.Fatal("timed out waiting for a health check to run")
		}
	}
	for range n {
		select {
		case d := <-r.waits:
			waits = append(waits, d)
		case <-time.After(3 * time.Second):
			r.t.Fatal("timed out waiting for a health check to wait for its next run")
		}
	}
	slices.Sort(waits)
	return waits
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

type blockingCheckable struct {
	release chan struct{}
}

func (b *blockingCheckable) CheckHealth() State {
	<-b.release
	return State{Live: true, Ready: true}
}

type countingCheckable struct {
	mtx   sync.Mutex
	state State
	calls int
}

func (c *countingCheckable) CheckHealth() State {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.calls++
	return c.state
}

func (c *countingCheckable) setState(state State) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.state = state
}

func (c *countingCheckable) count() int {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.calls
}
