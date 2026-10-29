//go:build !windows

package agent

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus/hooks/test"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type queueWiringManager struct {
	manager.Manager
	started chan struct{}
}

func (m *queueWiringManager) SubscribeToX509CacheChanges(context.Context, cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	m.started <- struct{}{}
	return wiringSubscriber{updates: make(chan *cache.X509WorkloadUpdate)}, nil
}

func TestActiveStreamLimitsAgentQueueWiring(t *testing.T) {
	log, _ := test.NewNullLogger()
	socket := filepath.Join(spiretest.TempDir(t), "queue.sock")
	config := &Config{BindAddress: &net.UnixAddr{Name: socket, Net: "unix"}, Log: log, TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}
	policy := reflect.ValueOf(config).Elem().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, policy.IsValid())
	for _, field := range []string{"Global", "MaxPending"} {
		v := policy.FieldByName(field)
		require.True(t, v.IsValid())
		v.SetInt(1)
	}
	mgr := &queueWiringManager{started: make(chan struct{}, 4)}
	endpoint := New(config).newEndpoints(fakemetrics.New(), mgr, wiringAttestor{})
	snapshot := reflect.ValueOf(endpoint).MethodByName("WorkloadAPIStreamStats")
	require.True(t, snapshot.IsValid())
	waitStats := func(a, p int) {
		t.Helper()
		require.Eventually(t, func() bool {
			s := snapshot.Call(nil)[0]
			return s.FieldByName("Active").Int() == int64(a) && s.FieldByName("Pending").Int() == int64(p)
		}, 5*time.Second, time.Millisecond)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- endpoint.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("endpoint did not stop")
		}
	})
	ready := make(chan struct{}, 1)
	go endpoint.WaitForListening(ready)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("endpoint did not listen")
	}
	conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	holderCtx, cancelHolder := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelHolder()
	holderCtx = metadata.AppendToOutgoingContext(holderCtx, "workload.spiffe.io", "true")
	holder, err := workloadpb.NewSpiffeWorkloadAPIClient(conn).FetchJWTBundles(holderCtx, &workloadpb.JWTBundlesRequest{})
	require.NoError(t, err)
	holderResult := make(chan error, 1)
	go func() { _, err := holder.Recv(); holderResult <- err }()
	select {
	case <-mgr.started:
	case err := <-holderResult:
		t.Fatalf("holder was rejected before subscribing: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("holder did not subscribe")
	}
	waitStats(1, 0)
	pendingCtx, cancelPending := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPending()
	pending, err := secretv3.NewSecretDiscoveryServiceClient(conn).StreamSecrets(pendingCtx)
	require.NoError(t, err)
	require.NoError(t, pending.Send(&discoveryv3.DiscoveryRequest{}))
	pendingResult := make(chan error, 1)
	go func() { _, err := pending.Recv(); pendingResult <- err }()
	waitStats(1, 1)
	cancelHolder()
	require.Equal(t, codes.Canceled, status.Code(<-holderResult))
	select {
	case <-mgr.started:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not hand capacity to queued SDS call")
	}
	waitStats(1, 0)
	cancelPending()
	require.Equal(t, codes.Canceled, status.Code(<-pendingResult))
	waitStats(0, 0)
}
