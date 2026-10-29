//go:build !windows

package agent

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus/hooks/test"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const wiringChildMode = "SPIRE_ACTIVE_STREAM_WIRING_CHILD"
const wiringSocket = "SPIRE_ACTIVE_STREAM_WIRING_SOCKET"
const wiringMethod = "SPIRE_ACTIVE_STREAM_WIRING_METHOD"

type wiringAttestor struct{}

func (wiringAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return []*common.Selector{{Type: "unix", Value: "shared"}}, nil
}

func (wiringAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return nil, nil
}

type wiringManager struct {
	manager.Manager
	started chan struct{}
}

func (m *wiringManager) SubscribeToX509CacheChanges(ctx context.Context, _ cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	updates := make(chan *cache.X509WorkloadUpdate, 1)
	if watcher, ok := peertracker.WatcherFromContext(ctx); ok && watcher.PID() == int32(os.Getpid()) {
		// The real health service accepts PermissionDenied when the agent has no
		// workload identity. Give its self-originated stream that response.
		updates <- &cache.X509WorkloadUpdate{}
	} else {
		m.started <- struct{}{}
	}
	return wiringSubscriber{updates: updates}, nil
}

type wiringSubscriber struct {
	updates <-chan *cache.X509WorkloadUpdate
}

func (s wiringSubscriber) Updates() <-chan *cache.X509WorkloadUpdate { return s.updates }
func (s wiringSubscriber) Finish()                                   {}

func TestActiveStreamLimitsAgentEndpointWiring(t *testing.T) {
	if mode := os.Getenv(wiringChildMode); mode != "" {
		runWiringChild(t, mode, os.Getenv(wiringSocket), os.Getenv(wiringMethod))
		return
	}

	log, _ := test.NewNullLogger()
	socket := filepath.Join(spiretest.TempDir(t), "agent.sock")
	config := &Config{
		BindAddress: &net.UnixAddr{Name: socket, Net: "unix"},
		Log:         log,
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	policy := reflect.ValueOf(config).Elem().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, policy.IsValid(), "agent must carry configured stream limits to its endpoints")
	endpointPolicy, ok := reflect.TypeFor[endpoints.Config]().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, ok)
	require.Equal(t, endpointPolicy.Type, policy.Type(), "agent and endpoint must expose the same public policy type")
	methods := []struct {
		name  string
		limit int
	}{
		{"FetchX509SVID", 1},
		{"FetchX509Bundles", 2},
		{"FetchJWTBundles", 3},
		{"StreamSecrets", 4},
	}
	for _, method := range methods {
		setting := policy.FieldByName(method.name)
		require.True(t, setting.IsValid(), "agent must carry %s limit", method.name)
		setting.SetInt(int64(method.limit))
	}

	mgr := &wiringManager{started: make(chan struct{}, 16)}
	endpoint := New(config).newEndpoints(fakemetrics.New(), mgr, wiringAttestor{})
	ctx, stop := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- endpoint.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-serverDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("agent endpoint did not stop")
		}
	})
	ready := make(chan struct{}, 1)
	go endpoint.WaitForListening(ready)
	select {
	case <-ready:
	case err := <-serverDone:
		t.Fatalf("agent endpoint failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("agent endpoint did not start")
	}

	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			for range method.limit {
				// #nosec G204 -- Re-execute this test binary with a fixed test selector to exercise distinct caller PIDs.
				holder := exec.Command(os.Args[0], "-test.run=^TestActiveStreamLimitsAgentEndpointWiring$")
				holder.Env = append(os.Environ(), wiringChildMode+"=hold", wiringSocket+"="+socket, wiringMethod+"="+method.name)
				require.NoError(t, holder.Start())
				holderDone := make(chan error, 1)
				go func() {
					holderDone <- holder.Wait()
					close(holderDone)
				}()
				t.Cleanup(func() {
					_ = holder.Process.Kill()
					<-holderDone
				})
				select {
				case <-mgr.started:
				case err := <-holderDone:
					t.Fatalf("holding workload exited before admission: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("holding workload did not open a stream")
				}
			}

			// #nosec G204 -- Re-execute this test binary with a fixed test selector to exercise distinct caller PIDs.
			probe := exec.Command(os.Args[0], "-test.run=^TestActiveStreamLimitsAgentEndpointWiring$")
			probe.Env = append(os.Environ(), wiringChildMode+"=probe", wiringSocket+"="+socket, wiringMethod+"="+method.name)
			output, err := probe.CombinedOutput()
			require.NoError(t, err, "next workload must receive ResourceExhausted at its own distinct ceiling: %s", output)
			if method.name == "FetchX509SVID" {
				conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
				require.NoError(t, err)
				defer conn.Close()
				checkCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				response, err := grpc_health_v1.NewHealthClient(conn).Check(checkCtx, &grpc_health_v1.HealthCheckRequest{})
				require.NoError(t, err)
				require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, response.Status, "the agent's real health-check RPC must remain healthy at saturation")
			}
		})
	}
}

func runWiringChild(t *testing.T, mode, socket, method string) {
	ctx := context.Background()
	if mode == "probe" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
	workload := workloadpb.NewSpiffeWorkloadAPIClient(conn)
	var receive func() error
	switch method {
	case "FetchX509SVID":
		stream, err := workload.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
		require.NoError(t, err)
		receive = func() error { _, err := stream.Recv(); return err }
	case "FetchX509Bundles":
		stream, err := workload.FetchX509Bundles(ctx, &workloadpb.X509BundlesRequest{})
		require.NoError(t, err)
		receive = func() error { _, err := stream.Recv(); return err }
	case "FetchJWTBundles":
		stream, err := workload.FetchJWTBundles(ctx, &workloadpb.JWTBundlesRequest{})
		require.NoError(t, err)
		receive = func() error { _, err := stream.Recv(); return err }
	case "StreamSecrets":
		stream, err := secret_v3.NewSecretDiscoveryServiceClient(conn).StreamSecrets(ctx)
		require.NoError(t, err)
		sendErr := stream.Send(&discovery_v3.DiscoveryRequest{})
		if mode == "hold" {
			require.NoError(t, sendErr)
		}
		receive = func() error { _, err := stream.Recv(); return err }
	default:
		t.Fatalf("unknown streaming method %s", method)
	}
	err = receive()
	if mode == "probe" {
		require.Equal(t, codes.ResourceExhausted, status.Code(err), "second workload must be denied at the configured active ceiling")
	}
}

func TestActiveStreamLimitsAgentAggregateWiring(t *testing.T) {
	for _, field := range []string{"Global", "PerWorkload", "Pools"} {
		t.Run(field, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			socket := filepath.Join(spiretest.TempDir(t), "agent.sock")
			config := &Config{
				BindAddress: &net.UnixAddr{Name: socket, Net: "unix"},
				Log:         log,
				TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			}
			policy := reflect.ValueOf(config).Elem().FieldByName("WorkloadAPIStreamLimits")
			require.True(t, policy.IsValid())
			setting := policy.FieldByName(field)
			require.True(t, setting.IsValid(), "agent must propagate %s", field)
			if field == "Pools" {
				require.Equal(t, reflect.Slice, setting.Kind())
				setting.Set(reflect.MakeSlice(setting.Type(), 1, 1))
				pool := setting.Index(0)
				pool.FieldByName("Name").SetString("all")
				pool.FieldByName("Selectors").Set(reflect.ValueOf([]string{}))
				pool.FieldByName("Limit").SetInt(1)
			} else {
				setting.SetInt(1)
			}
			mgr := &wiringManager{started: make(chan struct{}, 16)}
			endpoint := New(config).newEndpoints(fakemetrics.New(), mgr, wiringAttestor{})
			ctx, stop := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- endpoint.ListenAndServe(ctx) }()
			t.Cleanup(func() {
				stop()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Error("agent endpoint did not stop")
				}
			})
			ready := make(chan struct{}, 1)
			go endpoint.WaitForListening(ready)
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("agent endpoint did not listen")
			}
			// #nosec G204 -- Re-execute this test binary with a fixed test selector to exercise distinct caller PIDs.
			holder := exec.Command(os.Args[0], "-test.run=^TestActiveStreamLimitsAgentEndpointWiring$")
			holder.Env = append(os.Environ(), wiringChildMode+"=hold", wiringSocket+"="+socket, wiringMethod+"=FetchX509SVID")
			require.NoError(t, holder.Start())
			holderDone := make(chan error, 1)
			go func() { holderDone <- holder.Wait() }()
			t.Cleanup(func() { _ = holder.Process.Kill(); <-holderDone })
			select {
			case <-mgr.started:
			case <-time.After(5 * time.Second):
				t.Fatal("holding workload did not start")
			}
			// #nosec G204 -- Re-execute this test binary with a fixed test selector to exercise distinct caller PIDs.
			probe := exec.Command(os.Args[0], "-test.run=^TestActiveStreamLimitsAgentEndpointWiring$")
			probe.Env = append(os.Environ(), wiringChildMode+"=probe", wiringSocket+"="+socket, wiringMethod+"=StreamSecrets")
			output, err := probe.CombinedOutput()
			require.NoError(t, err, "agent must share %s across Workload API and SDS: %s", field, output)
			conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()
			checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			response, err := grpc_health_v1.NewHealthClient(conn).Check(checkCtx, &grpc_health_v1.HealthCheckRequest{})
			require.NoError(t, err)
			require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, response.Status)
		})
	}
}

func TestActiveStreamLimitsPublicAPICompatibility(t *testing.T) {
	// Compile an external caller: exported aliases satisfy the public contract
	// even when reflection reports the underlying type's different name.
	source := `package main
import (
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/endpoints"
)
func main() {
	policy := endpoints.WorkloadAPIStreamLimitsConfig{
		FetchX509SVID: 1, FetchX509Bundles: 2, FetchJWTBundles: 3,
		StreamSecrets: 4, PerWorkload: 5, Global: 6, MaxPending: 7,
        Pools: []endpoints.WorkloadAPIStreamPoolConfig{{Name: "namespace", Selectors: []string{"k8s:ns:shared"}, Limit: 3}},
	}
	_ = endpoints.Config{WorkloadAPIStreamLimits: policy}
	_ = agent.Config{WorkloadAPIStreamLimits: policy}
	var update func(endpoints.WorkloadAPIStreamLimitsConfig) error =
		(&endpoints.Endpoints{}).UpdateWorkloadAPIStreamLimits
	_ = update
	var stats func() endpoints.WorkloadAPIStreamStats = (&endpoints.Endpoints{}).WorkloadAPIStreamStats
	_ = stats
 var pools map[string]int = (endpoints.WorkloadAPIStreamStats{}).PoolActive
 _ = pools
}

`
	path := filepath.Join(t.TempDir(), "public_api.go")
	require.NoError(t, os.WriteFile(path, []byte(source), 0o600))
	output, err := exec.Command("go", "test", path).CombinedOutput()
	require.NoError(t, err, "the documented public policy API must compile: %s", output)
}
