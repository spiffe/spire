package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/pkg/agent/trustbundlesources"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/spiretest"
)

func TestCheckHealth(t *testing.T) {
	for _, tt := range []struct {
		name               string
		disableWorkloadAPI bool
		started            bool
		setupBindAddress   func(t *testing.T) net.Addr
		expectReady        bool
		expectLive         bool
		expectErr          string
	}{
		{
			name:        "public endpoint disabled",
			started:     true,
			expectReady: true,
			expectLive:  true,
		},
		{
			name:               "workload API disabled with serving endpoint",
			disableWorkloadAPI: true,
			started:            true,
			setupBindAddress: func(t *testing.T) net.Addr {
				return spiretest.StartGRPCServer(t, func(s *grpc.Server) {})
			},
			expectReady: true,
			expectLive:  true,
		},
		{
			name:               "workload API disabled with unavailable endpoint",
			disableWorkloadAPI: true,
			started:            true,
			setupBindAddress: func(t *testing.T) net.Addr {
				return spiretest.StartWorkloadAPI(t, unavailableWorkloadAPI{})
			},
			expectReady: false,
			expectLive:  false,
			expectErr:   "workload api is unavailable",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				DisableWorkloadAPI: tt.disableWorkloadAPI,
			}
			if tt.setupBindAddress != nil {
				c.BindAddress = tt.setupBindAddress(t)
			}

			a := New(c)
			a.started = tt.started

			state := a.CheckHealth()
			require.NotNil(t, state.Started)
			require.Equal(t, tt.started, *state.Started)
			require.Equal(t, tt.expectReady, state.Ready)
			require.Equal(t, tt.expectLive, state.Live)

			if tt.expectErr == "" {
				return
			}
			require.Equal(t, agentHealthDetails{
				WorkloadAPIErr: tt.expectErr,
			}, state.ReadyDetails)
			require.Equal(t, agentHealthDetails{
				WorkloadAPIErr: tt.expectErr,
			}, state.LiveDetails)
		})
	}
}

// TestMetricsServedDuringAttestationRetry asserts that the telemetry listener is
// already serving while node attestation is still retrying.
//
// Attestation retries for up to bootstrapBackoffMaxElapsedTime, or
// rebootstrapBackoffMaxElapsedTime when rebootstrapping, and every early return
// in that loop happens before the task batch at the end of Run. If
// metrics.ListenAndServe is started from that batch rather than before
// attestation, an agent that never attests successfully exposes no metrics at
// all - it is indistinguishable from an agent that is not running, which is the
// situation #6164 fixed. This test fails if that placement regresses.
func TestMetricsServedDuringAttestationRetry(t *testing.T) {
	log, _ := test.NewNullLogger()

	// Two free ports: one for the exporter to bind, and one with nothing behind it
	// so attestation fails with a retryable error and Run stays in its backoff
	// loop rather than returning.
	ports := reserveFreePorts(t, 2)
	promPort, deadServerPort := ports[0], ports[1]

	a := New(&Config{
		DataDir:         filepath.Join(t.TempDir(), "data"),
		Log:             log,
		TrustDomain:     spiffeid.RequireTrustDomainFromString("example.org"),
		ServerAddress:   fmt.Sprintf("127.0.0.1:%d", deadServerPort),
		RebootstrapMode: RebootstrapNever,
		// A join token keeps the node attestor out of the catalog; the failure being
		// exercised is the dial, not the attestor.
		JoinToken: "TOKEN",
		PluginConfigs: catalog.PluginConfigs{
			{Type: "KeyManager", Name: "memory"},
			{Type: "NodeAttestor", Name: "join_token"},
			{Type: "WorkloadAttestor", Name: "unix"},
		},
		// Insecure bootstrap keeps the test free of certificates and bundle files:
		// GetBundle returns no bundle, and attestation proceeds straight to the dial.
		TrustBundleSources: trustbundlesources.New(&trustbundlesources.Config{
			InsecureBootstrap: true,
			TrustDomain:       "example.org",
		}, log),
		Telemetry: telemetry.FileConfig{
			Prometheus: &telemetry.PrometheusConfig{Host: "127.0.0.1", Port: promPort},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(ctx) }()

	body := requireScrapeContains(t, promPort, runErr, "spire_agent_started")
	// Emitted from GetBundle on every attestation attempt, so its presence shows
	// the retry loop is observable and not merely that the socket is open.
	require.Contains(t, body, "spire_agent_bootstrap_attempts")

	cancel()
	select {
	case <-runErr:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for Run to return after context cancellation")
	}
}

// reserveFreePorts returns n distinct ports with nothing listening on them.
func reserveFreePorts(t *testing.T, n int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		require.NoError(t, l.Close())
	}
	return ports
}

// requireScrapeContains polls /metrics until it serves a body containing want,
// failing if the agent exits first or the deadline passes.
func requireScrapeContains(t *testing.T, port int, runErr <-chan error, want string) string {
	t.Helper()
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	// Bounded per-request timeout so a stalled response fails this attempt rather
	// than hanging until the outer deadline.
	client := &http.Client{Timeout: 2 * time.Second}

	// The condition runs on another goroutine, so these are mutex-guarded rather
	// than relying on require.Eventually's internal ordering.
	var (
		mu      sync.Mutex
		body    string
		lastErr error
		exitErr error
		exited  bool
	)

	require.Eventually(t, func() bool {
		select {
		case err := <-runErr:
			mu.Lock()
			exitErr, exited = err, true
			mu.Unlock()
			return true
		default:
		}

		got, err := scrapeOnce(client, endpoint)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			lastErr = err
			return false
		}
		if strings.Contains(got, want) {
			body = got
			return true
		}
		return false
	}, 30*time.Second, 100*time.Millisecond,
		"%q never became scrapeable on %s; "+
			"is metrics.ListenAndServe still started before node attestation in Run?",
		want, endpoint)

	mu.Lock()
	defer mu.Unlock()
	require.False(t, exited, "Run returned before %q was scrapeable: %v", want, exitErr)
	require.NotEmpty(t, body, "no metrics body captured (last scrape error: %v)", lastErr)
	return body
}

func scrapeOnce(client *http.Client, endpoint string) (string, error) {
	resp, err := client.Get(endpoint) //nolint: gosec // fixed loopback URL built in-test
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return string(body), nil
}

type unavailableWorkloadAPI struct {
	workload_pb.UnimplementedSpiffeWorkloadAPIServer
}

func (unavailableWorkloadAPI) FetchX509Bundles(_ *workload_pb.X509BundlesRequest, _ workload_pb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	return status.Error(codes.Unavailable, "")
}
