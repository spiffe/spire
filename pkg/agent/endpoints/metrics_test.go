package endpoints

import (
	"context"
	"testing"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/grpctest"
)

// TestDebugServiceConnectionMetrics verifies that Debug API calls going through
// the agent middleware do NOT produce misconfiguration error logs.
// Regression test for https://github.com/spiffe/spire/issues/5183
func TestDebugServiceConnectionMetrics(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	metrics := fakemetrics.New()

	server := grpctest.StartServer(t,
		func(s grpc.ServiceRegistrar) {
			debugv1.RegisterDebugServer(s, &fakeDebugServer{})
		},
		grpctest.Middleware(Middleware(log, metrics)),
	)

	conn := server.NewGRPCClient(t)
	client := debugv1.NewDebugClient(conn)

	_, _ = client.GetInfo(context.Background(), &debugv1.GetInfoRequest{})

	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.ErrorLevel {
			assert.NotContains(t, entry.Message, "unrecognized service for connection metrics",
				"Debug service should be recognized by connection metrics middleware")
		}
	}

	// Verify connection metrics are emitted with the correct metric key
	allMetrics := metrics.AllMetrics()
	require.NotEmpty(t, allMetrics)

	var foundConnectionCounter, foundGaugeUp, foundGaugeDown bool
	for _, m := range allMetrics {
		if m.Type == fakemetrics.IncrCounterType && assert.ObjectsAreEqual([]string{"debug_api", "connection"}, m.Key) {
			foundConnectionCounter = true
		}
		if m.Type == fakemetrics.SetGaugeType && assert.ObjectsAreEqual([]string{"debug_api", "connections"}, m.Key) && m.Val == 1 {
			foundGaugeUp = true
		}
		if m.Type == fakemetrics.SetGaugeType && assert.ObjectsAreEqual([]string{"debug_api", "connections"}, m.Key) && m.Val == 0 {
			foundGaugeDown = true
		}
	}
	assert.True(t, foundConnectionCounter, "Expected debug_api connection counter metric")
	assert.True(t, foundGaugeUp, "Expected debug_api connections gauge to increment")
	assert.True(t, foundGaugeDown, "Expected debug_api connections gauge to decrement")
}

// TestAllAgentServicesHandledByConnectionMetrics registers every gRPC service
// that the agent exposes (across both the Workload API and Admin API servers),
// makes a call to each one through the middleware, and asserts that none
// produce an "unrecognized service" misconfiguration log.
//
// IMPORTANT: When adding a new gRPC service to the agent, add it to this test.
// If a service is missing from the connectionMetrics switch in metrics.go, this
// test will catch it.
func TestAllAgentServicesHandledByConnectionMetrics(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	metrics := fakemetrics.New()

	server := grpctest.StartServer(t,
		func(s grpc.ServiceRegistrar) {
			workload_pb.RegisterSpiffeWorkloadAPIServer(s, &workload_pb.UnimplementedSpiffeWorkloadAPIServer{})
			secret_v3.RegisterSecretDiscoveryServiceServer(s, &secret_v3.UnimplementedSecretDiscoveryServiceServer{})
			grpc_health_v1.RegisterHealthServer(s, &grpc_health_v1.UnimplementedHealthServer{})
			debugv1.RegisterDebugServer(s, &fakeDebugServer{})
			delegatedidentityv1.RegisterDelegatedIdentityServer(s, &fakeDelegatedIdentityServer{})
		},
		grpctest.Middleware(Middleware(log, metrics)),
	)

	conn := server.NewGRPCClient(t)
	ctx := context.Background()

	// Call each agent service to exercise it through the middleware.
	// The connectionMetrics switch must handle every service listed here.
	t.Run("WorkloadAPI", func(t *testing.T) {
		hook.Reset()
		client := workload_pb.NewSpiffeWorkloadAPIClient(conn)
		_, _ = client.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{})
		assertNoMisconfigurationLog(t, hook)
	})

	t.Run("SDS", func(t *testing.T) {
		hook.Reset()
		client := secret_v3.NewSecretDiscoveryServiceClient(conn)
		_, _ = client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
		assertNoMisconfigurationLog(t, hook)
	})

	t.Run("Health", func(t *testing.T) {
		hook.Reset()
		client := grpc_health_v1.NewHealthClient(conn)
		_, _ = client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		assertNoMisconfigurationLog(t, hook)
	})

	t.Run("Debug", func(t *testing.T) {
		hook.Reset()
		client := debugv1.NewDebugClient(conn)
		_, _ = client.GetInfo(ctx, &debugv1.GetInfoRequest{})
		assertNoMisconfigurationLog(t, hook)
	})

	t.Run("DelegatedIdentity", func(t *testing.T) {
		hook.Reset()
		client := delegatedidentityv1.NewDelegatedIdentityClient(conn)
		_, _ = client.FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{})
		assertNoMisconfigurationLog(t, hook)
	})
}

func assertNoMisconfigurationLog(t *testing.T, hook *test.Hook) {
	t.Helper()
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.ErrorLevel {
			assert.NotContains(t, entry.Message, "unrecognized service for connection metrics",
				"Service should be recognized by the connection metrics middleware")
		}
	}
}

type fakeDebugServer struct {
	debugv1.UnimplementedDebugServer
}

type fakeDelegatedIdentityServer struct {
	delegatedidentityv1.UnimplementedDelegatedIdentityServer
}
