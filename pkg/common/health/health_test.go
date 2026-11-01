package health

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerDisabledByDefault(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker := NewChecker(Config{}, log).(*checker)

	assert.Nil(t, checker.server)
}

func TestServerEnabled(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker := NewChecker(Config{ListenerEnabled: true}, log).(*checker)

	assert.NotNil(t, checker.server)
}

func TestCheckerListeners(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	config := Config{
		ListenerEnabled: true,
		BindAddress:     "localhost",
		BindPort:        "12345",
	}

	servableChecker := NewChecker(config, log)

	fooChecker := &fakeCheckable{
		state: State{
			Live:         true,
			Ready:        true,
			ReadyDetails: healthDetails{},
			LiveDetails:  healthDetails{},
		},
	}
	err := servableChecker.AddCheck("foo", fooChecker)
	require.NoError(t, err)

	barChecker := &fakeCheckable{
		state: State{
			Live:         true,
			Ready:        true,
			ReadyDetails: healthDetails{},
			LiveDetails:  healthDetails{},
		},
	}
	err = servableChecker.AddCheck("bar", barChecker)
	require.NoError(t, err)

	// Get checker to set a chan in order to wait until sync is done
	finalChecker, ok := servableChecker.(*checker)
	require.True(t, ok)

	clk := clock.NewMock(t)
	finalChecker.cache.clk = clk

	waitFor := make(chan struct{}, 1)
	finalChecker.cache.hooks.statusUpdated = waitFor

	ctx := context.Background()

	go func() {
		_ = servableChecker.ListenAndServe(ctx)
	}()

	require.Eventuallyf(t, func() bool {
		_, err := net.Dial("tcp", "localhost:12345")
		return err == nil
	}, time.Minute, 50*time.Millisecond, "server didn't started in the required time")

	// Wait for the initial health check to complete before making HTTP requests.
	// Without this, the handler may see zero-value states (Ready=false) and
	// return 500 before the first checkFunc() has populated the cache.
	select {
	case <-waitFor:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timeout waiting for initial status update")
	}

	t.Run("success ready", func(t *testing.T) {
		resp, err := http.Get("http://localhost:12345/ready")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		actual, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.JSONEq(t, "{\"bar\":{},\"foo\":{}}\n", string(actual))
	})

	t.Run("success live", func(t *testing.T) {
		resp, err := http.Get("http://localhost:12345/live")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		actual, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.JSONEq(t, "{\"bar\":{},\"foo\":{}}\n", string(actual))
	})

	// Drain any pending signals from the initial health check loop
	select {
	case <-waitFor:
	default:
	}

	fooChecker.state.Live = false
	fooChecker.state.LiveDetails = healthDetails{Err: "live fails"}

	barChecker.state.Ready = false
	barChecker.state.ReadyDetails = healthDetails{Err: "ready fails"}

	// Advancing the mock clock only fires timers that already exist, so wait
	// for the steady-state loop to arm its timer before advancing.
	clk.WaitForAfter(5*time.Second, "timeout waiting for the steady-state health check timer")
	clk.Add(readyCheckInterval)

	select {
	case <-waitFor:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timeout waiting for status update")
	}

	t.Run("live fails", func(t *testing.T) {
		resp, err := http.Get("http://localhost:12345/live")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		actual, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.JSONEq(t, "{\"bar\":{},\"foo\":{\"err\":\"live fails\"}}\n", string(actual))
	})

	t.Run("ready fails", func(t *testing.T) {
		resp, err := http.Get("http://localhost:12345/ready")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		actual, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.JSONEq(t, "{\"bar\":{\"err\":\"ready fails\"},\"foo\":{}}\n", string(actual))
	})
}
