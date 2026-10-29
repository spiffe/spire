package endpoints

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/stretchr/testify/require"
)

type delayedStreamSubscriptionManager struct {
	manager.Manager
	entered chan struct{}
	resume  <-chan struct{}
}

func (m *delayedStreamSubscriptionManager) SubscribeToX509CacheChanges(ctx context.Context, selectors cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	sub, err := m.Manager.SubscribeToX509CacheChanges(ctx, selectors)
	close(m.entered)
	<-m.resume
	return sub, err
}

func TestActiveStreamLimitsSDSCloseDuringSubscription(t *testing.T) {
	for _, count := range []int{1, 4} {
		t.Run(fmt.Sprintf("%d_requests", count), func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			resumeSubscription := func() { once.Do(func() { close(resume) }) }
			defer resumeSubscription()
			c := newStreamTestClients(t, map[string]int{"Global": 1}, WorkloadAPIRateLimitConfig{}, nil, func(config *Config) {
				config.Manager = &delayedStreamSubscriptionManager{Manager: config.Manager, entered: entered, resume: resume}
			})
			ctx, cancel := streamCallContext(t, c, 1, 15*time.Second)
			stream, err := c.sds.StreamSecrets(ctx)
			require.NoError(t, err)
			for i := range count {
				require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{ResourceNames: []string{fmt.Sprintf("spiffe://example.org/unavailable-%d", i)}}))
			}
			waitStreamEvent(t, entered, "subscription setup")
			updates := <-c.manager.subscriptions
			t.Cleanup(func() {
				select {
				case updates <- &cache.X509WorkloadUpdate{}:
				default:
				}
			})
			waitQueueStats(t, c, 1, 0)
			require.NoError(t, stream.CloseSend())
			// Cache setup may be slower than the peer's request and half-close.
			// A receiver may either buffer them or leave them in the transport.
			time.Sleep(100 * time.Millisecond)
			resumeSubscription()
			done := make(chan error, 1)
			go func() { _, err := stream.Recv(); done <- err }()
			select {
			case err := <-done:
				require.ErrorIs(t, err, io.EOF)
			case <-time.After(5 * time.Second):
				t.Fatal("SDS half-close did not finish after subscription setup")
			}
			waitStreamEvent(t, c.manager.finished, "half-close subscription cleanup")
			waitQueueStats(t, c, 0, 0)
			cancel()
		})
	}
}
