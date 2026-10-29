package endpoints

import (
	"fmt"
	"io"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func requireNoWaitingSubscription(t *testing.T, c streamTestClients) {
	t.Helper()
	select {
	case <-c.manager.started:
		t.Fatal("waiting stream started a workload subscription")
	case <-c.manager.subscriptions:
		t.Fatal("waiting stream obtained workload updates")
	case <-c.manager.subscribedIDs:
		t.Fatal("waiting stream subscribed before admission")
	case <-time.After(25 * time.Millisecond):
	}
}

func TestActiveStreamLimitsPendingDoesNotSubscribe(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiter := queueStart(t, c, method, 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			requireNoWaitingSubscription(t, c)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, waiter)
			requireNoWaitingSubscription(t, c)
			queueStop(t, c, waiter, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsPendingSDSHalfClose(t *testing.T) {
	for _, scope := range []string{"global", "pool"} {
		for _, requests := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/%d_requests", scope, requests), func(t *testing.T) {
				c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
				if scope == "pool" {
					require.NoError(t, poolReplace(t, c, poolPolicy(t, map[string]int{"MaxPending": 1}, poolCase{"all", nil, 1})))
				}
				holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
				queueAdmitted(t, c, holder)
				ctx, cancel := streamCallContext(t, c, 3, 30*time.Second)
				stream, err := c.sds.StreamSecrets(ctx)
				require.NoError(t, err)
				for i := range requests {
					require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{ResourceNames: []string{fmt.Sprintf("resource-%d", i)}}))
				}
				waitQueueStats(t, c, 1, 1)
				requireNoWaitingSubscription(t, c)
				require.NoError(t, stream.CloseSend())
				done := make(chan error, 1)
				go func() { _, err := stream.Recv(); done <- err }()
				select {
				case err := <-done:
					require.ErrorIs(t, err, io.EOF, "half-close must finish a queued SDS stream")
				case <-time.After(5 * time.Second):
					t.Fatal("half-closed SDS call retained its pending position")
				}
				waitQueueStats(t, c, 1, 0)
				requireNoWaitingSubscription(t, c)
				require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "StreamSecrets"))
				cancel()
				next := queueStart(t, c, "FetchX509Bundles", 7, 30*time.Second)
				waitQueueStats(t, c, 1, 1)
				queueStop(t, c, holder, true)
				queueAdmitted(t, c, next)
				queueStop(t, c, next, true)
				waitQueueStats(t, c, 0, 0)
			})
		}
	}
}

func TestActiveStreamLimitsPendingSDSRequestRetained(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
	holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	ctx, cancel := streamCallContext(t, c, 3, 30*time.Second)
	stream, err := c.sds.StreamSecrets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{ResourceNames: []string{"spiffe://example.org/unavailable"}}))
	waitQueueStats(t, c, 1, 1)
	requireNoWaitingSubscription(t, c)
	queueStop(t, c, holder, true)
	waitStreamEvent(t, c.manager.started, "SDS admission")
	select {
	case updates := <-c.manager.subscriptions:
		updates <- &cache.X509WorkloadUpdate{}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted SDS stream did not subscribe")
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Recv(); done <- err }()
	select {
	case err := <-done:
		require.Equal(t, codes.InvalidArgument, status.Code(err), "the original resource request must be processed after admission")
	case <-time.After(5 * time.Second):
		t.Fatal("SDS request sent while waiting was lost")
	}
	waitStreamEvent(t, c.manager.finished, "SDS error cleanup")
	waitQueueStats(t, c, 0, 0)
	cancel()
}
