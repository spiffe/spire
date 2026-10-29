package endpoints

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func startupStreamClients(t *testing.T, limits map[string]int) (streamTestClients, string) {
	t.Helper()
	socket := filepath.Join(spiretest.TempDir(t), "startup.sock")
	clients := newStreamTestClients(t, limits, WorkloadAPIRateLimitConfig{}, nil, func(c *Config) {
		c.BindAddr = &net.UnixAddr{Name: socket, Net: "unix"}
	})
	return clients, socket
}

func observeStreamStartup(t *testing.T, c streamTestClients) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// Use the repository's existing listening hook without leaving a waiter
	// behind when policy validation rejects startup before listening.
	ready := make(chan struct{}, 1)
	c.endpoint.hooks.listening = ready
	go func() { done <- c.endpoint.ListenAndServe(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("endpoint did not stop after cancellation")
			}
		})
	}
	select {
	case err := <-done:
		cancel()
		return false, err
	case <-ready:
		t.Cleanup(stop)
		return true, nil
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("endpoint did not reach a startup decision")
		return false, nil
	}
}

func TestActiveStreamLimitsDirectStartupValidation(t *testing.T) {
	for _, field := range []struct{ name, key string }{
		{"FetchX509SVID", "fetch_x509_svid"},
		{"FetchX509Bundles", "fetch_x509_bundles"},
		{"FetchJWTBundles", "fetch_jwt_bundles"},
		{"StreamSecrets", "stream_secrets"},
		{"PerWorkload", "per_workload"},
		{"Global", "global"},
		{"MaxPending", "max_pending"},
	} {
		t.Run(field.name, func(t *testing.T) {
			c, socket := startupStreamClients(t, map[string]int{field.name: -1})
			// An occupied address distinguishes policy validation before binding
			// from validation performed only after a listener has been opened.
			occupied, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = occupied.Close() })
			started, err := observeStreamStartup(t, c)
			require.False(t, started, "negative stream policy must not start serving")
			require.Error(t, err)
			require.Contains(t, err.Error(), field.key, "startup must identify the offending configuration key before attempting to listen")
		})
	}
}

func TestActiveStreamLimitsPreStartPolicyReplacement(t *testing.T) {
	for _, previousAttempt := range []bool{false, true} {
		name := "before_first_start"
		if previousAttempt {
			name = "after_rejected_start"
		}
		t.Run(name, func(t *testing.T) {
			c, _ := startupStreamClients(t, map[string]int{"Global": -1})
			if previousAttempt {
				started, err := observeStreamStartup(t, c)
				require.False(t, started)
				require.Error(t, err)
				require.Contains(t, err.Error(), "global")
			}
			// Invalid replacements remain atomic even before the first start.
			err := replaceStreamPolicy(t, c, map[string]int{"PerWorkload": -1})
			require.Error(t, err)
			require.Contains(t, err.Error(), "per_workload")
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"FetchJWTBundles": 1, "Global": 2}))
			started, err := observeStreamStartup(t, c)
			require.NoError(t, err, "a valid replacement must correct the invalid initial policy")
			require.True(t, started)
			// The same endpoint's registered handlers must enforce the complete
			// replacement, not merely clear an earlier startup error.
			first := admitPolicyStream(t, c, "FetchJWTBundles", 1)
			rejectPolicyStream(t, c, "FetchJWTBundles", 2)
			second := admitPolicyStream(t, c, "StreamSecrets", 3)
			rejectPolicyStream(t, c, "FetchX509Bundles", 3)
			first()
			admitPolicyStream(t, c, "FetchX509Bundles", 3)()
			second()
		})
	}
}
