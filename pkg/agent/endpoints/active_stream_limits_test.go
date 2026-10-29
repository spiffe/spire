package endpoints

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus/hooks/test"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type streamTestWatcher struct{ pid int32 }

func (w streamTestWatcher) PID() int32     { return w.pid }
func (w streamTestWatcher) IsAlive() error { return nil }
func (w streamTestWatcher) Close()         {}

type streamTestAttestor struct{ FakeAttestor }

func (streamTestAttestor) Attest(_ context.Context, pid int) ([]*common.Selector, error) {
	switch pid - os.Getpid() {
	case 3:
		return []*common.Selector{{Type: "k8s", Value: "ns:other"}}, nil
	case 4:
		return nil, nil
	case 5:
		return []*common.Selector{}, nil
	case 6:
		return nil, fmt.Errorf("attestation rejected")
	case 7:
		return []*common.Selector{{Type: "k8s", Value: "ns:shared"}, {Type: "unix", Value: "uid:1000"}}, nil
	case 8:
		return []*common.Selector{{Type: "unix", Value: "uid:1000"}, {Type: "k8s", Value: "ns:shared"}}, nil
	case 9:
		return []*common.Selector{{Type: "unix", Value: "same-value"}}, nil
	case 10:
		return []*common.Selector{{Type: "k8s", Value: "same-value"}}, nil
	case 11:
		return []*common.Selector{{Type: "a", Value: "bc"}}, nil
	case 12:
		return []*common.Selector{{Type: "ab", Value: "c"}}, nil
	default:
		return []*common.Selector{{Type: "k8s", Value: "ns:shared"}}, nil
	}
}

type streamTestManager struct {
	manager.Manager
	mu                sync.Mutex
	active            int
	maxActive         int
	started           chan struct{}
	finished          chan struct{}
	subscriptions     chan chan *cache.X509WorkloadUpdate
	subscribedIDs     chan string
	subscribeFailures int
	workloadUpdate    *cache.X509WorkloadUpdate
	entries           []*common.RegistrationEntry
	jwtSVID           *client.JWTSVID
}

func (m *streamTestManager) SubscribeToX509CacheChanges(ctx context.Context, _ cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	m.mu.Lock()
	if m.subscribeFailures > 0 {
		m.subscribeFailures--
		m.mu.Unlock()
		return nil, status.Error(codes.Unavailable, "cache unavailable")
	}
	m.active++
	if m.active > m.maxActive {
		m.maxActive = m.active
	}
	m.mu.Unlock()
	updates := make(chan *cache.X509WorkloadUpdate, 1)
	m.subscriptions <- updates
	m.started <- struct{}{}
	if m.subscribedIDs != nil {
		md, _ := metadata.FromIncomingContext(ctx)
		m.subscribedIDs <- md.Get("test-stream-id")[0]
	}
	return &streamTestSubscriber{updates: updates, manager: m}, nil
}

func (m *streamTestManager) FetchWorkloadUpdate([]*common.Selector) *cache.X509WorkloadUpdate {
	if m.workloadUpdate != nil {
		return m.workloadUpdate
	}
	return &cache.X509WorkloadUpdate{}
}

func (m *streamTestManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	return m.entries
}

func (m *streamTestManager) FetchJWTSVID(context.Context, *common.RegistrationEntry, []string) (*client.JWTSVID, error) {
	return m.jwtSVID, nil
}

type streamTestSubscriber struct {
	updates <-chan *cache.X509WorkloadUpdate
	manager *streamTestManager
}

func (s *streamTestSubscriber) Updates() <-chan *cache.X509WorkloadUpdate { return s.updates }
func (s *streamTestSubscriber) Finish() {
	s.manager.mu.Lock()
	s.manager.active--
	s.manager.mu.Unlock()
	s.manager.finished <- struct{}{}
}

type streamTestClients struct {
	workload  workload_pb.SpiffeWorkloadAPIClient
	sds       secret_v3.SecretDiscoveryServiceClient
	manager   *streamTestManager
	metrics   *fakemetrics.FakeMetrics
	endpoint  *Endpoints
	completed *sync.Map
	sequence  *atomic.Int64
}

func newStreamTestClients(t *testing.T, limits map[string]int, rate WorkloadAPIRateLimitConfig, manager *streamTestManager, options ...func(*Config)) streamTestClients {
	t.Helper()
	if manager == nil {
		manager = &streamTestManager{}
	}
	manager.started = make(chan struct{}, 64)
	manager.finished = make(chan struct{}, 64)
	manager.subscriptions = make(chan chan *cache.X509WorkloadUpdate, 64)
	log, _ := test.NewNullLogger()
	metrics := fakemetrics.New()
	config := Config{
		Log:                         log,
		Metrics:                     metrics,
		Attestor:                    streamTestAttestor{},
		Manager:                     manager,
		TrustDomain:                 spiffeid.RequireTrustDomainFromString("example.org"),
		DisableSPIFFECertValidation: true,
		WorkloadAPIRateLimit:        rate,
	}
	for _, option := range options {
		option(&config)
	}
	policy := reflect.ValueOf(&config).Elem().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, policy.IsValid(), "the agent endpoint configuration must accept stream_limits")
	for method, limit := range limits {
		field := policy.FieldByName(method)
		require.True(t, field.IsValid(), "stream limit for %s is unavailable", method)
		require.Equal(t, reflect.Int, field.Kind(), "stream limit for %s must be an integer", method)
		field.SetInt(int64(limit))
	}
	e := New(config)
	completed := &sync.Map{}
	sequence := &atomic.Int64{}
	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		workload_pb.RegisterSpiffeWorkloadAPIServer(s, e.workloadAPIServer)
		secret_v3.RegisterSecretDiscoveryServiceServer(s, e.sdsv3Server)
	}, grpctest.OverrideContext(func(ctx context.Context) context.Context {
		caller := 1
		if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("test-caller")) == 1 {
			if parsed, err := strconv.Atoi(md.Get("test-caller")[0]); err == nil {
				caller = parsed
			}
		}
		return peer.NewContext(ctx, &peer.Peer{AuthInfo: peertracker.AuthInfo{Watcher: streamTestWatcher{pid: int32(os.Getpid() + caller)}}})
	}), grpctest.Middleware(
		middleware.WithLogger(log),
		middleware.Preprocess(addWatcherPID),
		middleware.Postprocess(func(ctx context.Context, _ string, _ bool, _ error) {
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				if ids := md.Get("test-stream-id"); len(ids) == 1 {
					if done, ok := completed.LoadAndDelete(ids[0]); ok {
						close(done.(chan struct{}))
					}
				}
			}
		}),
	))
	conn := server.NewGRPCClient(t)
	return streamTestClients{workload: workload_pb.NewSpiffeWorkloadAPIClient(conn), sds: secret_v3.NewSecretDiscoveryServiceClient(conn), manager: manager, metrics: metrics, endpoint: e, completed: completed, sequence: sequence}
}

func streamCallerContext(caller int, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("test-caller", strconv.Itoa(caller))), cancel
}

func streamCallContext(t *testing.T, c streamTestClients, caller int, timeout time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, stop := streamCallerContext(caller, timeout)
	id := strconv.FormatInt(c.sequence.Add(1), 10)
	done := make(chan struct{})
	c.completed.Store(id, done)
	ctx = metadata.AppendToOutgoingContext(ctx, "test-stream-id", id)
	cancel := func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("stream handler did not finish cleanup")
		}
	}
	t.Cleanup(cancel)
	return ctx, cancel
}

func startStream(t *testing.T, c streamTestClients, method string, caller int, timeout time.Duration) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := streamCallContext(t, c, caller, timeout)
	result := make(chan error, 1)
	switch method {
	case "FetchX509SVID":
		stream, err := c.workload.FetchX509SVID(ctx, &workload_pb.X509SVIDRequest{})
		require.NoError(t, err)
		go func() { _, err := stream.Recv(); result <- err }()
	case "FetchX509Bundles":
		stream, err := c.workload.FetchX509Bundles(ctx, &workload_pb.X509BundlesRequest{})
		require.NoError(t, err)
		go func() { _, err := stream.Recv(); result <- err }()
	case "FetchJWTBundles":
		stream, err := c.workload.FetchJWTBundles(ctx, &workload_pb.JWTBundlesRequest{})
		require.NoError(t, err)
		go func() { _, err := stream.Recv(); result <- err }()
	case "StreamSecrets":
		stream, err := c.sds.StreamSecrets(ctx)
		require.NoError(t, err)
		// A saturated server may reject before this send completes; Recv carries
		// the authoritative gRPC status in either ordering.
		_ = stream.Send(&discovery_v3.DiscoveryRequest{})
		go func() { _, err := stream.Recv(); result <- err }()
	default:
		cancel()
		t.Fatalf("unknown method %s", method)
	}
	return cancel, result
}

func waitStreamEvent(t *testing.T, event <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func expectStreamError(t *testing.T, result <-chan error, want codes.Code) {
	t.Helper()
	select {
	case err := <-result:
		require.Equal(t, want, status.Code(err), "unexpected stream result: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not finish")
	}
}

func TestActiveStreamLimitsAllMethods(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			cancel, first := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first subscription")
			cancelSecond, second := startStream(t, clients, method, 2, 5*time.Second)
			defer cancelSecond()
			expectStreamError(t, second, codes.ResourceExhausted)
			select {
			case err := <-first:
				t.Fatalf("rejecting a new %s stream terminated the established stream: %v", method, err)
			default:
			}
			cancel()
			expectStreamError(t, first, codes.Canceled)
			waitStreamEvent(t, clients.manager.finished, "cancelled stream cleanup")
			cancelThird, third := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "reconnected subscription")
			cancelThird()
			expectStreamError(t, third, codes.Canceled)
			waitStreamEvent(t, clients.manager.finished, "reconnected stream cleanup")
		})
	}
}

func TestActiveStreamLimitsSelectorSetsAndMethods(t *testing.T) {
	methods := []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"}
	limits := make(map[string]int, len(methods))
	for _, method := range methods {
		limits[method] = 1
	}
	clients := newStreamTestClients(t, limits, WorkloadAPIRateLimitConfig{}, nil)
	type admittedStream struct {
		cancel context.CancelFunc
		result <-chan error
	}
	var admitted []admittedStream
	for _, method := range methods {
		// Each method must admit the same selector set even while the other
		// methods already have an active stream for that set.
		for _, caller := range []int{1, 3, 4} {
			cancel, result := startStream(t, clients, method, caller, 20*time.Second)
			admitted = append(admitted, admittedStream{cancel, result})
			waitStreamEvent(t, clients.manager.started, "independent method and selector-set subscription")
		}
		for _, caller := range []int{2, 3, 5} {
			rejectCancel, rejected := startStream(t, clients, method, caller, 5*time.Second)
			expectStreamError(t, rejected, codes.ResourceExhausted)
			rejectCancel()
		}
	}
	for _, stream := range admitted {
		stream.cancel()
		expectStreamError(t, stream.result, codes.Canceled)
	}
	for range admitted {
		waitStreamEvent(t, clients.manager.finished, "independent stream cleanup")
	}
}

func TestActiveStreamLimitsZeroUnaryAndAgent(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		for _, mode := range []string{"zero", "omitted"} {
			t.Run(mode+"_"+method, func(t *testing.T) {
				var limits map[string]int
				if mode == "zero" {
					limits = map[string]int{method: 0}
				}
				unlimited := newStreamTestClients(t, limits, WorkloadAPIRateLimitConfig{}, nil)
				var cancels []context.CancelFunc
				var results []<-chan error
				for range 3 {
					cancel, result := startStream(t, unlimited, method, 1, 10*time.Second)
					cancels = append(cancels, cancel)
					results = append(results, result)
					waitStreamEvent(t, unlimited.manager.started, "unlimited stream with the same selectors")
				}
				for i, cancel := range cancels {
					cancel()
					expectStreamError(t, results[i], codes.Canceled)
				}
			})
		}
	}

	limited := newStreamTestClients(t, map[string]int{"FetchX509SVID": 1, "StreamSecrets": 1}, WorkloadAPIRateLimitConfig{}, nil)
	cancel, first := startStream(t, limited, "FetchX509SVID", 1, 10*time.Second)
	waitStreamEvent(t, limited.manager.started, "limited stream")
	selfCancel, self := startStream(t, limited, "FetchX509SVID", 0, 10*time.Second)
	waitStreamEvent(t, limited.manager.started, "agent-self stream")
	selfCancel()
	expectStreamError(t, self, codes.Canceled)
	ctx, done := streamCallerContext(2, 5*time.Second)
	defer done()
	_, err := limited.workload.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{Audience: []string{"test"}})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "unary identity handling must remain available")
	_, err = limited.workload.ValidateJWTSVID(ctx, &workload_pb.ValidateJWTSVIDRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "unary validation must remain available")
	sdsCancel, sdsStream := startStream(t, limited, "StreamSecrets", 1, 10*time.Second)
	waitStreamEvent(t, limited.manager.started, "limited SDS stream")
	_, err = limited.sds.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	require.NoError(t, err, "unary SDS fetch must remain available while StreamSecrets is full")
	sdsCancel()
	expectStreamError(t, sdsStream, codes.Canceled)
	cancel()
	expectStreamError(t, first, codes.Canceled)
}

func TestActiveStreamLimitsAgentSelfOnlyHealthExemption(t *testing.T) {
	for _, method := range []string{"FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1, "Global": 2, "PerWorkload": 2}, WorkloadAPIRateLimitConfig{}, nil)
			cancel, first := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "ordinary workload fills stream allowance")
			selfCancel, self := startStream(t, clients, method, 0, 5*time.Second)
			expectStreamError(t, self, codes.ResourceExhausted)
			selfCancel()
			cancel()
			expectStreamError(t, first, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsEarlyFailureAndMetric(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			failed := newStreamTestClients(t, map[string]int{method: 1, "Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, &streamTestManager{subscribeFailures: 1})
			cancelFailure, failure := startStream(t, failed, method, 1, 5*time.Second)
			expectStreamError(t, failure, codes.Unavailable)
			cancelFailure()
			cancelReconnect, reconnected := startStream(t, failed, method, 1, 10*time.Second)
			waitStreamEvent(t, failed.manager.started, "reconnect after early failure")
			cancelReconnect()
			expectStreamError(t, reconnected, codes.Canceled)
			waitStreamEvent(t, failed.manager.finished, "reconnected stream cleanup")
		})
	}
}

func TestActiveStreamLimitsEstablishedStreamError(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1, "Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
			cancel, first := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "established stream")
			updates := <-clients.manager.subscriptions
			updates <- &cache.X509WorkloadUpdate{}
			expectStreamError(t, first, codes.PermissionDenied)
			waitStreamEvent(t, clients.manager.finished, "server-side error cleanup")
			cancel()
			reconnectCancel, reconnected := startStream(t, clients, method, 2, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "reconnect after established stream error")
			reconnectCancel()
			expectStreamError(t, reconnected, codes.Canceled)
		})
	}

	t.Run("StreamSecrets", func(t *testing.T) {
		clients := newStreamTestClients(t, map[string]int{"StreamSecrets": 1, "Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
		ctx, cancel := streamCallContext(t, clients, 1, 10*time.Second)
		t.Cleanup(cancel)
		stream, err := clients.sds.StreamSecrets(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{ResourceNames: []string{"unavailable-secret"}}))
		result := make(chan error, 1)
		go func() { _, err := stream.Recv(); result <- err }()
		waitStreamEvent(t, clients.manager.started, "established SDS stream")
		updates := <-clients.manager.subscriptions
		updates <- &cache.X509WorkloadUpdate{}
		expectStreamError(t, result, codes.InvalidArgument)
		waitStreamEvent(t, clients.manager.finished, "SDS response error cleanup")
		cancel()
		reconnectCancel, reconnected := startStream(t, clients, "StreamSecrets", 2, 10*time.Second)
		waitStreamEvent(t, clients.manager.started, "SDS reconnect after server error")
		reconnectCancel()
		expectStreamError(t, reconnected, codes.Canceled)
	})
}

func TestActiveStreamLimitsDeadlineRelease(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1, "Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
			deadlineCancel, expired := startStream(t, clients, method, 1, 750*time.Millisecond)
			waitStreamEvent(t, clients.manager.started, "stream before deadline")
			expectStreamError(t, expired, codes.DeadlineExceeded)
			waitStreamEvent(t, clients.manager.finished, "deadline cleanup")
			deadlineCancel()
			reconnectCancel, reconnected := startStream(t, clients, method, 2, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "reconnect after deadline")
			reconnectCancel()
			expectStreamError(t, reconnected, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsSDSHalfCloseRelease(t *testing.T) {
	clients := newStreamTestClients(t, map[string]int{"StreamSecrets": 1, "Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
	ctx, cancel := streamCallContext(t, clients, 1, 10*time.Second)
	t.Cleanup(cancel)
	stream, err := clients.sds.StreamSecrets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{}))
	waitStreamEvent(t, clients.manager.started, "SDS stream before half-close")
	require.NoError(t, stream.CloseSend())
	_, err = stream.Recv()
	require.True(t, errors.Is(err, io.EOF), "SDS half-close should finish the stream: %v", err)
	waitStreamEvent(t, clients.manager.finished, "SDS half-close cleanup")
	cancel()
	reconnectCancel, reconnected := startStream(t, clients, "StreamSecrets", 2, 10*time.Second)
	waitStreamEvent(t, clients.manager.started, "SDS reconnect after half-close")
	reconnectCancel()
	expectStreamError(t, reconnected, codes.Canceled)
}

func TestActiveStreamLimitsMetrics(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1, "Global": 2, "PerWorkload": 2}, WorkloadAPIRateLimitConfig{}, nil)
			cancel, first := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first metric test stream")
			otherCancel, other := startStream(t, clients, method, 3, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "second selector-set metric test stream")
			require.Empty(t, streamLimitRejectionMetrics(clients.metrics.AllMetrics(), method), "admitted calls must not count as rejections")
			for _, caller := range []int{2, 3} {
				rejectCancel, rejected := startStream(t, clients, method, caller, 5*time.Second)
				expectStreamError(t, rejected, codes.ResourceExhausted)
				rejectCancel()
			}
			metrics := streamLimitRejectionMetrics(clients.metrics.AllMetrics(), method)
			require.Len(t, metrics, 2, "each rejected opening must increment the method aggregate once")
			require.Equal(t, fmt.Sprint(metrics[0].Key, metrics[0].Labels), fmt.Sprint(metrics[1].Key, metrics[1].Labels), "different callers and selector sets must share the method metric")
			for _, metric := range metrics {
				require.Equal(t, float64(1), metric.Val)
				require.NotEqual(t, []string{"workload_api", "rate_limit_exceeded"}, metric.Key,
					"active-slot rejections must not be counted as per-second rate denials")
				require.Len(t, metric.Labels, 1, "active-slot rejection metric must have only the method label")
				require.Equal(t, "method", metric.Labels[0].Name)
				require.Contains(t, normalizeStreamMetricIdentity(metric.Labels[0].Value), normalizeStreamMetricIdentity(method), "method label must identify the rejected RPC")
				for _, label := range metric.Labels {
					name := normalizeStreamMetricIdentity(label.Name)
					for _, forbidden := range []string{"selector", "caller", "pid", "workload"} {
						require.NotContains(t, name, forbidden, "rejection metric must not expose caller dimensions")
					}
				}
			}
			cancel()
			otherCancel()
			expectStreamError(t, first, codes.Canceled)
			expectStreamError(t, other, codes.Canceled)
		})
	}
}

func streamLimitRejectionMetrics(items []fakemetrics.MetricItem, method string) []fakemetrics.MetricItem {
	var matched []fakemetrics.MetricItem
	for _, item := range items {
		if item.Type != fakemetrics.IncrCounterWithLabelsType && item.Type != fakemetrics.IncrCounterType {
			continue
		}
		if reflect.DeepEqual(item.Key, []string{"workload_api", "rate_limit_exceeded"}) {
			continue
		}
		identity := normalizeStreamMetricIdentity(fmt.Sprint(item.Key, item.Labels))
		if strings.Contains(identity, normalizeStreamMetricIdentity(method)) {
			matched = append(matched, item)
		}
	}
	return matched
}

func normalizeStreamMetricIdentity(value string) string {
	var normalized strings.Builder
	for _, char := range strings.ToLower(value) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			normalized.WriteRune(char)
		}
	}
	return normalized.String()
}

func TestActiveStreamLimitsRateLimitIndependence(t *testing.T) {
	setupTestClock(t)
	for _, tc := range []struct {
		method string
		rate   func(int) WorkloadAPIRateLimitConfig
	}{
		{"FetchX509Bundles", func(n int) WorkloadAPIRateLimitConfig { return WorkloadAPIRateLimitConfig{FetchX509Bundles: n} }},
		{"StreamSecrets", func(n int) WorkloadAPIRateLimitConfig { return WorkloadAPIRateLimitConfig{StreamSecrets: n} }},
	} {
		t.Run(tc.method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{tc.method: 10}, tc.rate(2), nil)
			var cancels []context.CancelFunc
			var results []<-chan error
			for range 2 {
				cancel, result := startStream(t, clients, tc.method, 1, 10*time.Second)
				cancels = append(cancels, cancel)
				results = append(results, result)
				waitStreamEvent(t, clients.manager.started, "rate-limited admitted stream")
			}
			rejectCancel, rejected := startStream(t, clients, tc.method, 1, 5*time.Second)
			expectStreamError(t, rejected, codes.Unavailable)
			rejectCancel()
			for i, cancel := range cancels {
				cancel()
				expectStreamError(t, results[i], codes.Canceled)
			}

			streamCap := newStreamTestClients(t, map[string]int{tc.method: 1}, tc.rate(100), nil)
			cancel, first := startStream(t, streamCap, tc.method, 1, 10*time.Second)
			waitStreamEvent(t, streamCap.manager.started, "stream-limited admitted stream")
			rejectCancel, rejected = startStream(t, streamCap, tc.method, 1, 5*time.Second)
			expectStreamError(t, rejected, codes.ResourceExhausted)
			rejectCancel()
			cancel()
			expectStreamError(t, first, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsConcurrentOpen(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			const callers = 16
			var cancels []context.CancelFunc
			results := make(chan error, callers)
			for range callers {
				cancel, result := startStream(t, clients, method, 1, 20*time.Second)
				cancels = append(cancels, cancel)
				go func() { results <- <-result }()
			}
			defer func() {
				for _, cancel := range cancels {
					cancel()
				}
			}()
			waitStreamEvent(t, clients.manager.started, "one admitted concurrent stream")
			for range callers - 1 {
				select {
				case err := <-results:
					require.Equal(t, codes.ResourceExhausted, status.Code(err), "concurrent opening exceeded the configured ceiling")
				case <-time.After(10 * time.Second):
					t.Fatal("concurrent openings did not receive prompt admission decisions")
				}
			}
			clients.manager.mu.Lock()
			active, maxActive := clients.manager.active, clients.manager.maxActive
			clients.manager.mu.Unlock()
			require.Equal(t, 1, active)
			require.Equal(t, 1, maxActive)
		})
	}
}

func TestActiveStreamLimitsConcurrentLargerCeiling(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 3}, WorkloadAPIRateLimitConfig{}, nil)
			const callers = 12
			var cancels []context.CancelFunc
			results := make(chan error, callers)
			for range callers {
				cancel, result := startStream(t, clients, method, 1, 20*time.Second)
				cancels = append(cancels, cancel)
				go func() { results <- <-result }()
			}
			defer func() {
				for _, cancel := range cancels {
					cancel()
				}
			}()
			for range 3 {
				waitStreamEvent(t, clients.manager.started, "concurrent admission below ceiling three")
			}
			for range callers - 3 {
				select {
				case err := <-results:
					require.Equal(t, codes.ResourceExhausted, status.Code(err))
				case <-time.After(10 * time.Second):
					t.Fatal("concurrent openings did not resolve at ceiling three")
				}
			}
			clients.manager.mu.Lock()
			active, maxActive := clients.manager.active, clients.manager.maxActive
			clients.manager.mu.Unlock()
			require.Equal(t, 3, active)
			require.Equal(t, 3, maxActive)
		})
	}
}

func TestActiveStreamLimitsLargerCeiling(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		for _, ceiling := range []int{2, 3, 4} {
			t.Run(fmt.Sprintf("%s_%d", method, ceiling), func(t *testing.T) {
				clients := newStreamTestClients(t, map[string]int{method: ceiling}, WorkloadAPIRateLimitConfig{}, nil)
				var cancels []context.CancelFunc
				var results []<-chan error
				for range ceiling {
					cancel, result := startStream(t, clients, method, 1, 10*time.Second)
					cancels = append(cancels, cancel)
					results = append(results, result)
					waitStreamEvent(t, clients.manager.started, "admitted stream under configured ceiling")
				}
				rejectCancel, rejected := startStream(t, clients, method, 2, 5*time.Second)
				expectStreamError(t, rejected, codes.ResourceExhausted)
				rejectCancel()
				cancels[0]()
				expectStreamError(t, results[0], codes.Canceled)
				waitStreamEvent(t, clients.manager.finished, "released stream slot")
				reconnectCancel, reconnected := startStream(t, clients, method, 2, 10*time.Second)
				waitStreamEvent(t, clients.manager.started, "replacement stream")
				clients.manager.mu.Lock()
				maxActive := clients.manager.maxActive
				clients.manager.mu.Unlock()
				require.Equal(t, ceiling, maxActive)
				reconnectCancel()
				expectStreamError(t, reconnected, codes.Canceled)
				for i := 1; i < len(cancels); i++ {
					cancels[i]()
					expectStreamError(t, results[i], codes.Canceled)
				}
			})
		}
	}
}

func TestActiveStreamLimitsAfterAttestation(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			cancel, first := startStream(t, clients, method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "full allowance")
			failCancel, failed := startStream(t, clients, method, 6, 5*time.Second)
			expectStreamError(t, failed, codes.Unavailable)
			failCancel()
			cancel()
			expectStreamError(t, first, codes.Canceled)
			waitStreamEvent(t, clients.manager.finished, "released allowance")
			reconnectCancel, reconnected := startStream(t, clients, method, 2, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "post-attestation reconnect")
			reconnectCancel()
			expectStreamError(t, reconnected, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsOmittedBlock(t *testing.T) {
	clients := newStreamTestClients(t, nil, WorkloadAPIRateLimitConfig{FetchX509Bundles: 2}, nil)
	var cancels []context.CancelFunc
	var results []<-chan error
	for range 2 {
		cancel, result := startStream(t, clients, "FetchX509Bundles", 1, 10*time.Second)
		cancels = append(cancels, cancel)
		results = append(results, result)
		waitStreamEvent(t, clients.manager.started, "stream with omitted active limit")
	}
	rejectCancel, rejected := startStream(t, clients, "FetchX509Bundles", 1, 5*time.Second)
	expectStreamError(t, rejected, codes.Unavailable)
	rejectCancel()
	for i, cancel := range cancels {
		cancel()
		expectStreamError(t, results[i], codes.Canceled)
	}
}

func TestActiveStreamLimitsRateAdmissionOrder(t *testing.T) {
	clock := setupTestClock(t)
	for _, tc := range []struct {
		method string
		rate   WorkloadAPIRateLimitConfig
	}{
		{"FetchX509SVID", WorkloadAPIRateLimitConfig{FetchX509SVID: 1}},
		{"FetchX509Bundles", WorkloadAPIRateLimitConfig{FetchX509Bundles: 1}},
		{"FetchJWTBundles", WorkloadAPIRateLimitConfig{FetchJWTBundles: 1}},
		{"StreamSecrets", WorkloadAPIRateLimitConfig{StreamSecrets: 1}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{tc.method: 1}, tc.rate, nil)
			cancel, first := startStream(t, clients, tc.method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first rate-admitted stream")
			rateCancel, rateRejected := startStream(t, clients, tc.method, 1, 5*time.Second)
			expectStreamError(t, rateRejected, codes.Unavailable)
			rateCancel()
			clock.Add(time.Second)
			capCancel, capRejected := startStream(t, clients, tc.method, 1, 5*time.Second)
			expectStreamError(t, capRejected, codes.ResourceExhausted)
			capCancel()
			cancel()
			expectStreamError(t, first, codes.Canceled)
			waitStreamEvent(t, clients.manager.finished, "released stream after rate check")
			clock.Add(time.Second)
			reconnectCancel, reconnected := startStream(t, clients, tc.method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "stream after rate refill")
			reconnectCancel()
			expectStreamError(t, reconnected, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsRateDeniedDoesNotConsumeFreeSlot(t *testing.T) {
	clock := setupTestClock(t)
	for _, tc := range []struct {
		method string
		rate   WorkloadAPIRateLimitConfig
	}{
		{"FetchX509SVID", WorkloadAPIRateLimitConfig{FetchX509SVID: 1}},
		{"FetchX509Bundles", WorkloadAPIRateLimitConfig{FetchX509Bundles: 1}},
		{"FetchJWTBundles", WorkloadAPIRateLimitConfig{FetchJWTBundles: 1}},
		{"StreamSecrets", WorkloadAPIRateLimitConfig{StreamSecrets: 1}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{tc.method: 1}, tc.rate, nil)
			cancel, first := startStream(t, clients, tc.method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first rate-admitted stream")
			cancel()
			expectStreamError(t, first, codes.Canceled)
			waitStreamEvent(t, clients.manager.finished, "free active slot after cancellation")
			rateCancel, rateRejected := startStream(t, clients, tc.method, 1, 5*time.Second)
			expectStreamError(t, rateRejected, codes.Unavailable)
			rateCancel()
			clock.Add(time.Second)
			reconnectCancel, reconnected := startStream(t, clients, tc.method, 1, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "admission after rate denial with free slot")
			reconnectCancel()
			expectStreamError(t, reconnected, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsDifferentSelectorTypes(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			firstCancel, first := startStream(t, clients, method, 9, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first selector type")
			secondCancel, second := startStream(t, clients, method, 10, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "different selector type with same value")
			firstCancel()
			secondCancel()
			expectStreamError(t, first, codes.Canceled)
			expectStreamError(t, second, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsSelectorSerializationCollision(t *testing.T) {
	for _, method := range []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		t.Run(method, func(t *testing.T) {
			clients := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			firstCancel, first := startStream(t, clients, method, 11, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "first selector boundary")
			secondCancel, second := startStream(t, clients, method, 12, 10*time.Second)
			waitStreamEvent(t, clients.manager.started, "different selector boundary")
			firstCancel()
			secondCancel()
			expectStreamError(t, first, codes.Canceled)
			expectStreamError(t, second, codes.Canceled)
		})
	}
}

func TestActiveStreamLimitsSelectorSetIdentity(t *testing.T) {
	clients := newStreamTestClients(t, map[string]int{"FetchX509Bundles": 1}, WorkloadAPIRateLimitConfig{}, nil)
	cancel, first := startStream(t, clients, "FetchX509Bundles", 7, 10*time.Second)
	waitStreamEvent(t, clients.manager.started, "two-selector stream")
	rejectCancel, reordered := startStream(t, clients, "FetchX509Bundles", 8, 5*time.Second)
	expectStreamError(t, reordered, codes.ResourceExhausted)
	rejectCancel()
	cancel()
	expectStreamError(t, first, codes.Canceled)
}
