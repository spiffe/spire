package endpoints

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var policyMethods = []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"}

func replaceStreamPolicy(t *testing.T, c streamTestClients, limits map[string]int) error {
	t.Helper()
	update := reflect.ValueOf(c.endpoint).MethodByName("UpdateWorkloadAPIStreamLimits")
	require.True(t, update.IsValid(), "endpoints must support live stream policy replacement")
	require.Equal(t, 1, update.Type().NumIn())
	require.Equal(t, 1, update.Type().NumOut())
	field, ok := reflect.TypeFor[Config]().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, ok)
	require.Equal(t, field.Type, update.Type().In(0))
	require.Equal(t, reflect.TypeFor[error](), update.Type().Out(0))
	policy := reflect.New(update.Type().In(0)).Elem()
	require.Equal(t, reflect.Struct, policy.Kind())
	for name, value := range limits {
		field := policy.FieldByName(name)
		require.True(t, field.IsValid(), "policy must expose %s", name)
		require.Equal(t, reflect.Int, field.Kind())
		field.SetInt(int64(value))
	}
	result := update.Call([]reflect.Value{policy})[0]
	require.True(t, result.Type().Implements(reflect.TypeFor[error]()))
	if result.IsNil() {
		return nil
	}
	return result.Interface().(error)
}

func admitPolicyStream(t *testing.T, c streamTestClients, method string, caller int) func() {
	t.Helper()
	cancel, result := startStream(t, c, method, caller, 30*time.Second)
	waitStreamEvent(t, c.manager.started, "admitted stream")
	return func() {
		cancel()
		expectStreamError(t, result, codes.Canceled)
	}
}

func rejectPolicyStream(t *testing.T, c streamTestClients, method string, caller int) {
	t.Helper()
	cancel, result := startStream(t, c, method, caller, 30*time.Second)
	expectStreamError(t, result, codes.ResourceExhausted)
	cancel()
}

func TestActiveStreamLimitsGlobalAcrossAPIs(t *testing.T) {
	for i, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{"Global": 1}, WorkloadAPIRateLimitConfig{}, nil)
			stop := admitPolicyStream(t, c, method, 1)
			next := policyMethods[(i+1)%len(policyMethods)]
			rejectPolicyStream(t, c, next, 3)
			stop()
			admitPolicyStream(t, c, next, 3)()
		})
	}
}

func TestActiveStreamLimitsPerWorkloadAcrossMethods(t *testing.T) {
	for i, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{"PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
			stop := admitPolicyStream(t, c, method, 1)
			next := policyMethods[(i+1)%len(policyMethods)]
			rejectPolicyStream(t, c, next, 2)
			other := admitPolicyStream(t, c, next, 3)
			stop()
			admitPolicyStream(t, c, next, 2)()
			other()
		})
	}
	for _, callers := range [][2]int{{4, 5}, {7, 8}} {
		t.Run(fmt.Sprint(callers), func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{"PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
			stop := admitPolicyStream(t, c, "FetchJWTBundles", callers[0])
			rejectPolicyStream(t, c, "StreamSecrets", callers[1])
			stop()
		})
	}
}

func TestActiveStreamLimitsAdmissionIsAllOrNothing(t *testing.T) {
	c := newStreamTestClients(t, map[string]int{"Global": 3, "PerWorkload": 2, "FetchX509SVID": 1}, WorkloadAPIRateLimitConfig{}, nil)
	first := admitPolicyStream(t, c, "FetchX509SVID", 1)
	// A method denial must leave both aggregate allowances available.
	rejectPolicyStream(t, c, "FetchX509SVID", 2)
	second := admitPolicyStream(t, c, "FetchJWTBundles", 2)
	// A workload denial must not consume global capacity.
	rejectPolicyStream(t, c, "StreamSecrets", 1)
	third := admitPolicyStream(t, c, "StreamSecrets", 3)
	// A global denial must leave the other workload's local capacity available.
	rejectPolicyStream(t, c, "FetchX509SVID", 3)
	second()
	fourth := admitPolicyStream(t, c, "FetchX509SVID", 3)
	first()
	third()
	fourth()
}

func TestActiveStreamLimitsLivePolicyRetainsStreams(t *testing.T) {
	fields := append([]string{"Global", "PerWorkload"}, policyMethods...)
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			method := field
			if field == "Global" || field == "PerWorkload" {
				method = "FetchX509Bundles"
			}
			c := newStreamTestClients(t, nil, WorkloadAPIRateLimitConfig{}, nil)
			first := admitPolicyStream(t, c, method, 1)
			second := admitPolicyStream(t, c, method, 2)
			third := admitPolicyStream(t, c, method, 1)
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 1}))
			rejectPolicyStream(t, c, method, 2)
			// Releases from the old unlimited policy must drain current accounting.
			first()
			rejectPolicyStream(t, c, method, 2)
			second()
			rejectPolicyStream(t, c, method, 2)
			third()
			fourth := admitPolicyStream(t, c, method, 2)
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 2}))
			fifth := admitPolicyStream(t, c, method, 1)
			rejectPolicyStream(t, c, method, 2)
			require.NoError(t, replaceStreamPolicy(t, c, nil))
			sixth := admitPolicyStream(t, c, method, 2)
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 1}))
			rejectPolicyStream(t, c, method, 1)
			fourth()
			fifth()
			rejectPolicyStream(t, c, method, 2)
			sixth()
			admitPolicyStream(t, c, method, 1)()
		})
	}
}

func TestActiveStreamLimitsRejectedPolicyIsAtomic(t *testing.T) {
	keys := map[string]string{"Global": "global", "PerWorkload": "per_workload", "FetchX509SVID": "fetch_x509_svid", "FetchX509Bundles": "fetch_x509_bundles", "FetchJWTBundles": "fetch_jwt_bundles", "StreamSecrets": "stream_secrets"}
	for field, key := range keys {
		t.Run(field, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{"Global": 2, "PerWorkload": 1, "FetchX509SVID": 1}, WorkloadAPIRateLimitConfig{}, nil)
			first := admitPolicyStream(t, c, "FetchX509SVID", 1)
			second := admitPolicyStream(t, c, "StreamSecrets", 3)
			// A tempting partial replacement disables all other ceilings.
			err := replaceStreamPolicy(t, c, map[string]int{field: -1})
			require.Error(t, err)
			require.Contains(t, err.Error(), key)
			rejectPolicyStream(t, c, "FetchJWTBundles", 4)
			second()
			rejectPolicyStream(t, c, "StreamSecrets", 2)
			first()
			third := admitPolicyStream(t, c, "FetchX509SVID", 1)
			rejectPolicyStream(t, c, "FetchX509SVID", 2)
			third()
		})
	}
}

func TestActiveStreamLimitsLivePolicyAcrossAPIsAndInstances(t *testing.T) {
	first := newStreamTestClients(t, nil, WorkloadAPIRateLimitConfig{}, nil)
	second := newStreamTestClients(t, map[string]int{"Global": 1}, WorkloadAPIRateLimitConfig{}, nil)
	one := admitPolicyStream(t, first, "FetchJWTBundles", 1)
	two := admitPolicyStream(t, second, "StreamSecrets", 1)
	require.NoError(t, replaceStreamPolicy(t, first, map[string]int{"Global": 1}))
	rejectPolicyStream(t, first, "StreamSecrets", 3)
	rejectPolicyStream(t, second, "FetchJWTBundles", 3)
	require.NoError(t, replaceStreamPolicy(t, first, nil))
	three := admitPolicyStream(t, first, "StreamSecrets", 3)
	rejectPolicyStream(t, second, "FetchJWTBundles", 3)
	one()
	two()
	three()
}

func TestActiveStreamLimitsAggregateRejectionMetrics(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{"Global": 1, "PerWorkload": 1, method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			stop := admitPolicyStream(t, c, method, 1)
			rejectPolicyStream(t, c, method, 2)
			rejectPolicyStream(t, c, method, 3)
			metrics := streamLimitRejectionMetrics(c.metrics.AllMetrics(), method)
			require.Len(t, metrics, 2, "one increment per rejection, regardless of the number of exhausted ceilings")
			for _, metric := range metrics {
				require.Equal(t, float64(1), metric.Val)
				require.Len(t, metric.Labels, 1)
				require.Equal(t, "method", metric.Labels[0].Name)
			}
			stop()
		})
	}
}

func TestActiveStreamLimitsConcurrentAggregateAdmission(t *testing.T) {
	for _, tc := range []struct {
		name         string
		limits       map[string]int
		ceiling      int
		sameWorkload bool
	}{
		{"combined", map[string]int{"Global": 3, "PerWorkload": 2}, 3, false},
		{"per_workload_only", map[string]int{"PerWorkload": 2}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newStreamTestClients(t, tc.limits, WorkloadAPIRateLimitConfig{}, nil)
			gate := make(chan struct{})
			errors := make(chan error, 16)
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Go(func() {
					<-gate
					caller := 1
					if !tc.sameWorkload && i%2 == 1 {
						caller = 3
					}
					_, result := startStream(t, c, policyMethods[i%4], caller, 30*time.Second)
					go func() { errors <- <-result }()
				})
			}
			close(gate)
			wg.Wait()
			admitted := 0
			rejected := 0
			for range 16 {
				select {
				case <-c.manager.started:
					admitted++
				case err := <-errors:
					require.Equal(t, codes.ResourceExhausted, status.Code(err))
					rejected++
				case <-time.After(5 * time.Second):
					t.Fatal("concurrent admission did not settle")
				}
			}
			require.Equal(t, tc.ceiling, admitted)
			require.Equal(t, 16-tc.ceiling, rejected)
			c.manager.mu.Lock()
			active := c.manager.active
			maximum := c.manager.maxActive
			c.manager.mu.Unlock()
			require.Equal(t, tc.ceiling, active)
			require.Equal(t, tc.ceiling, maximum)
		})
	}
}

func TestActiveStreamLimitsConcurrentPolicySnapshots(t *testing.T) {
	c := newStreamTestClients(t, nil, WorkloadAPIRateLimitConfig{}, nil)
	first := admitPolicyStream(t, c, "FetchJWTBundles", 1)
	second := admitPolicyStream(t, c, "StreamSecrets", 2)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1}))
	stop := make(chan struct{})
	done := make(chan struct{})
	var stopOnce sync.Once
	stopUpdates := func() { stopOnce.Do(func() { close(stop) }); <-done }
	t.Cleanup(stopUpdates)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1}))
				require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"PerWorkload": 1}))
			}
		}
	}()
	// Both complete policies deny these calls. A mixed unlimited policy does not.
	for range 24 {
		rejectPolicyStream(t, c, "FetchX509Bundles", 1)
	}
	stopUpdates()
	first()
	second()
}

func TestActiveStreamLimitsConcurrentRejectedPolicy(t *testing.T) {
	c := newStreamTestClients(t, map[string]int{"Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
	first := admitPolicyStream(t, c, "FetchJWTBundles", 1)
	update := reflect.ValueOf(c.endpoint).MethodByName("UpdateWorkloadAPIStreamLimits")
	require.True(t, update.IsValid())
	fields := append([]string{"Global", "PerWorkload"}, policyMethods...)
	policies := make([]reflect.Value, 0, len(fields))
	for _, field := range fields {
		policy := reflect.New(update.Type().In(0)).Elem()
		setting := policy.FieldByName(field)
		require.True(t, setting.IsValid())
		setting.SetInt(-1)
		policies = append(policies, policy)
	}
	stop := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	stopUpdates := func() {
		once.Do(func() {
			close(stop)
			require.NoError(t, <-done)
		})
	}
	t.Cleanup(stopUpdates)
	go func() {
		started := false
		for {
			for _, policy := range policies {
				if update.Call([]reflect.Value{policy})[0].IsNil() {
					if !started {
						close(ready)
					}
					done <- fmt.Errorf("negative replacement was accepted")
					return
				}
			}
			if !started {
				close(ready)
				started = true
			}
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
		}
	}()
	waitStreamEvent(t, ready, "rejected policy replacements")
	// An invalid replacement must never make an exhausted old policy permissive.
	for i := range 48 {
		cancel, result := startStream(t, c, policyMethods[i%len(policyMethods)], 2+i%2, 30*time.Second)
		select {
		case <-c.manager.started:
			cancel()
			t.Fatal("invalid replacement admitted a stream through the exhausted old policy")
		case err := <-result:
			cancel()
			require.Equal(t, codes.ResourceExhausted, status.Code(err))
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("concurrent admission did not settle")
		}
	}
	stopUpdates()
	first()
	admitPolicyStream(t, c, "StreamSecrets", 3)()
}

func TestActiveStreamLimitsAggregateExemptions(t *testing.T) {
	c := newStreamTestClients(t, map[string]int{"Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
	self := admitPolicyStream(t, c, "FetchX509SVID", 0)
	ordinary := admitPolicyStream(t, c, "FetchJWTBundles", 1)
	for _, method := range []string{"FetchX509Bundles", "FetchJWTBundles", "StreamSecrets"} {
		rejectPolicyStream(t, c, method, 0)
	}
	ctx, cancel := streamCallerContext(2, 5*time.Second)
	defer cancel()
	_, err := c.workload.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{Audience: []string{"test"}})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = c.workload.ValidateJWTSVID(ctx, &workload_pb.ValidateJWTSVIDRequest{Audience: "test", Svid: "not-a-jwt"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = c.sds.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	require.NoError(t, err)
	ordinary()
	// Unary requests and the still-open health stream must not leave reservations.
	admitPolicyStream(t, c, "StreamSecrets", 3)()
	self()
}

func TestActiveStreamLimitsAggregateBeforeAdmission(t *testing.T) {
	clock := setupTestClock(t)
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			rate := WorkloadAPIRateLimitConfig{}
			reflect.ValueOf(&rate).Elem().FieldByName(method).SetInt(1)
			c := newStreamTestClients(t, map[string]int{"Global": 1, "PerWorkload": 1}, rate, nil)
			stop := admitPolicyStream(t, c, method, 1)
			stop()
			cancel, denied := startStream(t, c, method, 2, 30*time.Second)
			expectStreamError(t, denied, codes.Unavailable)
			cancel()
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), method), "rate denial must not increment active rejections")
			// Another method can consume the still-free aggregate slot immediately.
			other := "StreamSecrets"
			if method == other {
				other = "FetchJWTBundles"
			}
			admitPolicyStream(t, c, other, 2)()
			clock.Add(time.Second)
			cancel, denied = startStream(t, c, method, 6, 30*time.Second)
			expectStreamError(t, denied, codes.Unavailable)
			cancel()
			admitPolicyStream(t, c, other, 2)()
			admitPolicyStream(t, c, method, 2)()
		})
	}
}

func TestActiveStreamLimitsAggregateAfterFirstResponse(t *testing.T) {
	for _, scope := range []string{"StreamSecrets", "Global", "PerWorkload"} {
		t.Run("StreamSecrets_"+scope, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{scope: 1}, WorkloadAPIRateLimitConfig{}, nil)
			ctx, cancel := streamCallContext(t, c, 1, 30*time.Second)
			stream, err := c.sds.StreamSecrets(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{}))
			waitStreamEvent(t, c.manager.started, "SDS subscription")
			updates := <-c.manager.subscriptions
			updates <- &cache.X509WorkloadUpdate{}
			response, err := stream.Recv()
			require.NoError(t, err, "first SDS response must succeed")
			denied := "FetchJWTBundles"
			caller := 2
			if scope == "StreamSecrets" {
				denied = "StreamSecrets"
			}
			if scope == "Global" {
				caller = 3
			}
			rejectPolicyStream(t, c, denied, caller)
			require.NoError(t, stream.Send(&discovery_v3.DiscoveryRequest{ResourceNames: []string{"unavailable-secret"}, ResponseNonce: response.Nonce, VersionInfo: response.VersionInfo}))
			_, err = stream.Recv()
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			cancel()
			admitPolicyStream(t, c, "StreamSecrets", caller)()
		})
	}
	for _, method := range policyMethods[:3] {
		for _, scope := range []string{method, "Global", "PerWorkload"} {
			t.Run(method+"_"+scope, func(t *testing.T) {
				c := newStreamTestClients(t, map[string]int{scope: 1}, WorkloadAPIRateLimitConfig{}, nil)
				ctx, cancel := streamCallContext(t, c, 1, 30*time.Second)
				var recv func() error
				switch method {
				case "FetchX509SVID":
					stream, err := c.workload.FetchX509SVID(ctx, &workload_pb.X509SVIDRequest{})
					require.NoError(t, err)
					recv = func() error { _, err := stream.Recv(); return err }
				case "FetchX509Bundles":
					stream, err := c.workload.FetchX509Bundles(ctx, &workload_pb.X509BundlesRequest{})
					require.NoError(t, err)
					recv = func() error { _, err := stream.Recv(); return err }
				case "FetchJWTBundles":
					stream, err := c.workload.FetchJWTBundles(ctx, &workload_pb.JWTBundlesRequest{})
					require.NoError(t, err)
					recv = func() error { _, err := stream.Recv(); return err }
				}
				waitStreamEvent(t, c.manager.started, "Workload API subscription")
				updates := <-c.manager.subscriptions
				td := spiffeid.RequireTrustDomainFromString("example.org")
				ca := testca.New(t, td)
				svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
				updates <- &cache.X509WorkloadUpdate{Bundle: ca.Bundle(), Identities: []cache.X509Identity{{Entry: &common.RegistrationEntry{SpiffeId: svid.ID.String()}, PrivateKey: svid.PrivateKey, SVID: svid.Certificates}}}
				require.NoError(t, recv(), "first Workload API response must succeed")
				// Sending a response does not end the stream or release its reservation.
				denied := "StreamSecrets"
				caller := 2
				if scope == method {
					denied = method
				}
				if scope == "Global" {
					caller = 3
				}
				rejectPolicyStream(t, c, denied, caller)
				updates <- &cache.X509WorkloadUpdate{}
				require.Equal(t, codes.PermissionDenied, status.Code(recv()))
				cancel()
				admitPolicyStream(t, c, method, caller)()
			})
		}
	}
}

func prepareSuccessfulStreamUnary(t *testing.T, c streamTestClients) func() {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/workload")
	ca := testca.New(t, td)
	svid := ca.CreateJWTSVID(id, []string{"test"})
	c.manager.entries = []*common.RegistrationEntry{{SpiffeId: id.String()}}
	c.manager.jwtSVID = &client.JWTSVID{Token: svid.Marshal(), ExpiresAt: time.Now().Add(time.Hour)}
	c.manager.workloadUpdate = &cache.X509WorkloadUpdate{Bundle: ca.Bundle()}
	return func() {
		t.Helper()
		ctx, cancel := streamCallerContext(2, 5*time.Second)
		defer cancel()
		fetched, err := c.workload.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{Audience: []string{"test"}})
		require.NoError(t, err)
		require.Len(t, fetched.Svids, 1)
		require.Equal(t, svid.Marshal(), fetched.Svids[0].Svid)
		validated, err := c.workload.ValidateJWTSVID(ctx, &workload_pb.ValidateJWTSVIDRequest{Audience: "test", Svid: svid.Marshal()})
		require.NoError(t, err)
		require.Equal(t, id.String(), validated.SpiffeId)
		_, err = c.sds.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
		require.NoError(t, err)
	}
}

func TestActiveStreamLimitsSuccessfulUnaryAtSaturation(t *testing.T) {
	c := newStreamTestClients(t, map[string]int{"Global": 1, "PerWorkload": 1}, WorkloadAPIRateLimitConfig{}, nil)
	check := prepareSuccessfulStreamUnary(t, c)
	stop := admitPolicyStream(t, c, "StreamSecrets", 1)
	check()
	stop()
	admitPolicyStream(t, c, "FetchJWTBundles", 2)()
}

func TestActiveStreamLimitsQueueUnaryAtSaturation(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 1, "PerWorkload": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
	check := prepareSuccessfulStreamUnary(t, c)
	holder := queueStart(t, c, "StreamSecrets", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	waiting := queueStart(t, c, "FetchJWTBundles", 2, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	check()
	waitQueueStats(t, c, 1, 1)
	queueStop(t, c, holder, true)
	queueAdmitted(t, c, waiting)
	queueStop(t, c, waiting, true)
	waitQueueStats(t, c, 0, 0)
}
