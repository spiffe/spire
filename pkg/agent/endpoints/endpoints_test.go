package endpoints

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/hashicorp/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
)

func TestEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, tt := range []struct {
		name            string
		fromRemote      bool
		do              func(t *testing.T, conn *grpc.ClientConn)
		expectedLogs    []spiretest.LogEntry
		expectedMetrics []fakemetrics.MetricItem
		expectClaims    map[string]struct{}
		allowedClaims   []string
	}{
		{
			name: "workload api fails without security header",
			do: func(t *testing.T, conn *grpc.ClientConn) {
				wlClient := workload_pb.NewSpiffeWorkloadAPIClient(conn)
				_, err := wlClient.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{})
				spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, "security header missing from request")
			},
			expectedMetrics: []fakemetrics.MetricItem{
				// Global connection counter and then the increment/decrement of the connection gauge
				{Type: fakemetrics.IncrCounterType, Key: []string{"workload_api", "connection"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"workload_api", "connections"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"workload_api", "connections"}, Val: 0},
				// Call counter
				{Type: fakemetrics.IncrCounterWithLabelsType, Key: []string{"rpc", "workload_api", "fetch_jwtsvid"}, Val: 1, Labels: []metrics.Label{
					{Name: "status", Value: "InvalidArgument"},
				}},
				{Type: fakemetrics.MeasureSinceWithLabelsType, Key: []string{"rpc", "workload_api", "fetch_jwtsvid", "elapsed_time"}, Val: 0, Labels: []metrics.Label{
					{Name: "status", Value: "InvalidArgument"},
				}},
			},
			allowedClaims: []string{"c1"},
			expectClaims:  map[string]struct{}{"c1": {}},
		},
		{
			name: "workload api has peertracker attestor plumbed",
			do: func(t *testing.T, conn *grpc.ClientConn) {
				wlClient := workload_pb.NewSpiffeWorkloadAPIClient(conn)
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))
				_, err := wlClient.FetchJWTSVID(ctx, &workload_pb.JWTSVIDRequest{})
				require.NoError(t, err)
			},
			expectedLogs: []spiretest.LogEntry{
				logEntryWithPID(logrus.InfoLevel, "Success",
					"method", "FetchJWTSVID",
					"service", "WorkloadAPI",
				),
			},
			expectedMetrics: []fakemetrics.MetricItem{
				// Global connection counter and then the increment/decrement of the connection gauge
				{Type: fakemetrics.IncrCounterType, Key: []string{"workload_api", "connection"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"workload_api", "connections"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"workload_api", "connections"}, Val: 0},
				// RPC call counter is intentionally not emitted: the caller
				// PID matches the agent PID (os.Getpid()), so the middleware
				// discards per-call metrics to avoid health-check noise.
			},
		},
		{
			name: "sds v3 api has peertracker attestor plumbed",
			do: func(t *testing.T, conn *grpc.ClientConn) {
				sdsClient := secret_v3.NewSecretDiscoveryServiceClient(conn)
				_, err := sdsClient.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
				require.NoError(t, err)
			},
			expectedLogs: []spiretest.LogEntry{
				logEntryWithPID(logrus.InfoLevel, "Success",
					"method", "FetchSecrets",
					"service", "SDS.v3",
				),
			},
			expectedMetrics: []fakemetrics.MetricItem{
				// Global connection counter and then the increment/decrement of the connection gauge
				{Type: fakemetrics.IncrCounterType, Key: []string{"sds_api", "connection"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"sds_api", "connections"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"sds_api", "connections"}, Val: 0},
				// RPC call counter is intentionally not emitted: the caller
				// PID matches the agent PID (os.Getpid()), so the middleware
				// discards per-call metrics to avoid health-check noise.
			},
		},
		{
			name:       "access denied to remote caller",
			fromRemote: true,
		},
		{
			name: "reflection enabled",
			do: func(t *testing.T, conn *grpc.ClientConn) {
				exposedServices := []string{
					middleware.WorkloadAPIServiceName,
					middleware.EnvoySDSv3ServiceName,
					middleware.HealthServiceName,
					middleware.ServerReflectionServiceName,
					middleware.ServerReflectionV1AlphaServiceName,
				}
				client := grpc_reflection_v1.NewServerReflectionClient(conn)

				clientStream, err := client.ServerReflectionInfo(ctx)
				require.NoError(t, err)

				err = clientStream.Send(&grpc_reflection_v1.ServerReflectionRequest{
					MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{},
				})
				require.NoError(t, err)

				resp, err := clientStream.Recv()
				require.NoError(t, err)

				listResp := resp.GetListServicesResponse()
				require.NotNil(t, listResp)

				var serviceNames []string
				for _, service := range listResp.Service {
					serviceNames = append(serviceNames, service.Name)
				}
				assert.ElementsMatch(t, exposedServices, serviceNames)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			metrics := fakemetrics.New()
			addr := getTestAddr(t)
			endpoints := New(Config{
				BindAddr:                    addr,
				Log:                         log,
				Metrics:                     metrics,
				Attestor:                    FakeAttestor{},
				Manager:                     FakeManager{},
				DefaultSVIDName:             "DefaultSVIDName",
				DefaultBundleName:           "DefaultBundleName",
				DefaultAllBundlesName:       "DefaultAllBundlesName",
				DisableSPIFFECertValidation: true,
				AllowedForeignJWTClaims:     tt.allowedClaims,
				LogSelectors:                []string{"k8s:ns"},

				// Assert the provided config and return a fake Workload API server
				newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					assert.Equal(t, []string{"k8s:ns"}, c.LogSelectors)
					if tt.expectClaims != nil {
						assert.Equal(t, tt.expectClaims, c.AllowedForeignJWTClaims)
					} else {
						assert.Empty(t, c.AllowedForeignJWTClaims)
					}
					return FakeWorkloadAPIServer{Attestor: attestor}
				},

				// Assert the provided config and return a fake SDS server
				newSDSv3Server: func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					assert.Equal(t, "DefaultSVIDName", c.DefaultSVIDName)
					assert.Equal(t, "DefaultBundleName", c.DefaultBundleName)
					assert.Equal(t, "DefaultAllBundlesName", c.DefaultAllBundlesName)
					assert.Equal(t, true, c.DisableSPIFFECertValidation)
					return FakeSDSv3Server{Attestor: attestor}
				},

				// Assert the provided config and return a fake health server
				newHealthServer: func(c healthv1.Config) grpc_health_v1.HealthServer {
					assert.Equal(t, addr.String(), c.Addr.String())
					return FakeHealthServer{}
				},
			})
			endpoints.hooks.listening = make(chan struct{})

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- endpoints.ListenAndServe(ctx)
			}()
			defer func() {
				cancel()
				assert.NoError(t, <-errCh)
			}()
			waitForListening(t, endpoints, errCh)
			target, err := util.GetTargetName(endpoints.addr)
			require.NoError(t, err)

			if tt.fromRemote {
				testRemoteCaller(t, target)
				return
			}

			conn, err := util.NewGRPCClient(target)
			require.NoError(t, err)
			defer conn.Close()

			tt.do(t, conn)

			spiretest.AssertLogs(t, hook.AllEntries(), append([]spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Starting Workload and SDS APIs",
					Data: logrus.Fields{
						"address": endpoints.addr.String(),
						"network": addr.Network(),
					},
				},
			}, tt.expectedLogs...))
			assert.Equal(t, tt.expectedMetrics, metrics.AllMetrics())
		})
	}
}

func TestEndpointsDisableAPIs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	baseServices := []string{
		middleware.HealthServiceName,
		middleware.ServerReflectionServiceName,
		middleware.ServerReflectionV1AlphaServiceName,
	}

	for _, tt := range []struct {
		name                string
		disableWorkloadAPI  bool
		disableSDSAPI       bool
		expectedServices    []string
		expectWorkloadCode  codes.Code
		expectSDSCode       codes.Code
		expectWorkloadBuilt bool
		expectSDSBuilt      bool
	}{
		{
			name:                "both APIs enabled",
			expectedServices:    append(baseServices, middleware.WorkloadAPIServiceName, middleware.EnvoySDSv3ServiceName),
			expectWorkloadCode:  codes.OK,
			expectSDSCode:       codes.OK,
			expectWorkloadBuilt: true,
			expectSDSBuilt:      true,
		},
		{
			name:                "workload API disabled",
			disableWorkloadAPI:  true,
			expectedServices:    append(baseServices, middleware.EnvoySDSv3ServiceName),
			expectWorkloadCode:  codes.Unimplemented,
			expectSDSCode:       codes.OK,
			expectWorkloadBuilt: false,
			expectSDSBuilt:      true,
		},
		{
			name:                "SDS API disabled",
			disableSDSAPI:       true,
			expectedServices:    append(baseServices, middleware.WorkloadAPIServiceName),
			expectWorkloadCode:  codes.OK,
			expectSDSCode:       codes.Unimplemented,
			expectWorkloadBuilt: true,
			expectSDSBuilt:      false,
		},
		{
			name:                "both APIs disabled",
			disableWorkloadAPI:  true,
			disableSDSAPI:       true,
			expectedServices:    baseServices,
			expectWorkloadCode:  codes.Unimplemented,
			expectSDSCode:       codes.Unimplemented,
			expectWorkloadBuilt: false,
			expectSDSBuilt:      false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			metrics := fakemetrics.New()
			addr := getTestAddr(t)
			var workloadBuilt bool
			var sdsBuilt bool

			endpoints := New(Config{
				BindAddr:              addr,
				Log:                   log,
				Metrics:               metrics,
				Attestor:              FakeAttestor{},
				Manager:               FakeManager{},
				DisableWorkloadAPI:    tt.disableWorkloadAPI,
				DisableSDSAPI:         tt.disableSDSAPI,
				DefaultSVIDName:       "DefaultSVIDName",
				DefaultBundleName:     "DefaultBundleName",
				DefaultAllBundlesName: "DefaultAllBundlesName",
				newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
					workloadBuilt = true
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					return FakeWorkloadAPIServer{Attestor: attestor}
				},
				newSDSv3Server: func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
					sdsBuilt = true
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					return FakeSDSv3Server{Attestor: attestor}
				},
				newHealthServer: func(c healthv1.Config) grpc_health_v1.HealthServer {
					assert.Equal(t, tt.disableWorkloadAPI, c.DisableWorkloadAPI)
					return FakeHealthServer{}
				},
			})
			endpoints.hooks.listening = make(chan struct{})

			serveCtx, stopServing := context.WithCancel(ctx)
			defer stopServing()
			errCh := make(chan error, 1)
			go func() {
				errCh <- endpoints.ListenAndServe(serveCtx)
			}()
			defer func() {
				stopServing()
				assert.NoError(t, <-errCh)
			}()
			waitForListening(t, endpoints, errCh)

			target, err := util.GetTargetName(endpoints.addr)
			require.NoError(t, err)
			conn, err := util.NewGRPCClient(target)
			require.NoError(t, err)
			defer conn.Close()

			assert.Equal(t, tt.expectWorkloadBuilt, workloadBuilt)
			assert.Equal(t, tt.expectSDSBuilt, sdsBuilt)
			assert.ElementsMatch(t, tt.expectedServices, listServices(ctx, t, conn))

			callCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))
			wlClient := workload_pb.NewSpiffeWorkloadAPIClient(conn)
			_, err = wlClient.FetchJWTSVID(callCtx, &workload_pb.JWTSVIDRequest{})
			if tt.expectWorkloadCode == codes.OK {
				require.NoError(t, err)
			} else {
				require.Equal(t, tt.expectWorkloadCode, status.Code(err))
			}

			sdsClient := secret_v3.NewSecretDiscoveryServiceClient(conn)
			_, err = sdsClient.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
			if tt.expectSDSCode == codes.OK {
				require.NoError(t, err)
			} else {
				require.Equal(t, tt.expectSDSCode, status.Code(err))
			}
		})
	}
}

func listServices(ctx context.Context, t *testing.T, conn *grpc.ClientConn) []string {
	client := grpc_reflection_v1.NewServerReflectionClient(conn)
	clientStream, err := client.ServerReflectionInfo(ctx)
	require.NoError(t, err)

	err = clientStream.Send(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{},
	})
	require.NoError(t, err)

	resp, err := clientStream.Recv()
	require.NoError(t, err)

	listResp := resp.GetListServicesResponse()
	require.NotNil(t, listResp)

	var serviceNames []string
	for _, service := range listResp.Service {
		serviceNames = append(serviceNames, service.Name)
	}
	return serviceNames
}

type FakeManager struct {
	manager.Manager
}

type FakeWorkloadAPIServer struct {
	Attestor    PeerTrackerAttestor
	RateLimiter workload.RateLimiter
	workload_pb.UnimplementedSpiffeWorkloadAPIServer
}

func (s FakeWorkloadAPIServer) FetchJWTSVID(ctx context.Context, _ *workload_pb.JWTSVIDRequest) (*workload_pb.JWTSVIDResponse, error) {
	selectors, err := attest(ctx, s.Attestor)
	if err != nil {
		return nil, err
	}
	if s.RateLimiter != nil {
		if err := s.RateLimiter.RateLimit(workload.MethodFetchJWTSVID, selectors); err != nil {
			return nil, err
		}
	}
	return &workload_pb.JWTSVIDResponse{}, nil
}

type FakeSDSv3Server struct {
	Attestor    PeerTrackerAttestor
	RateLimiter sdsv3.RateLimiter
	*secret_v3.UnimplementedSecretDiscoveryServiceServer
}

func (s FakeSDSv3Server) FetchSecrets(ctx context.Context, _ *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	selectors, err := attest(ctx, s.Attestor)
	if err != nil {
		return nil, err
	}
	if s.RateLimiter != nil {
		if err := s.RateLimiter.RateLimit(sdsv3.MethodFetchSecrets, selectors); err != nil {
			return nil, err
		}
	}
	return &discovery_v3.DiscoveryResponse{}, nil
}

type FakeHealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func attest(ctx context.Context, attestor PeerTrackerAttestor) ([]*common.Selector, error) {
	log := rpccontext.Logger(ctx)
	selectors, err := attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to attest")
		return nil, err
	}
	if len(selectors) == 0 {
		log.Error("Permission denied")
		return nil, status.Error(codes.PermissionDenied, "attestor did not return selectors")
	}
	log.Info("Success")
	return selectors, nil
}

func logEntryWithPID(level logrus.Level, msg string, keyvalues ...any) spiretest.LogEntry {
	data := logrus.Fields{
		telemetry.PID: fmt.Sprint(os.Getpid()),
	}
	for i := 0; i < len(keyvalues); i += 2 {
		key := keyvalues[i]
		var value any
		if (i + 1) < len(keyvalues) {
			value = keyvalues[i+1]
		}
		data[key.(string)] = value
	}
	return spiretest.LogEntry{Level: level, Message: msg, Data: data}
}

func waitForListening(t *testing.T, e *Endpoints, errCh chan error) {
	select {
	case <-e.hooks.listening:
	case err := <-errCh:
		assert.Fail(t, err.Error())
	}
}

// TestEndpointsWorkloadRateLimitIntegration wires rate limiting through the
// full Endpoints → gRPC stack and verifies that requests are rejected with
// Unavailable once the per-caller burst is exhausted.
func TestEndpointsWorkloadRateLimitIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	log, _ := test.NewNullLogger()
	fm := fakemetrics.New()
	addr := getTestAddr(t)

	e := New(Config{
		BindAddr:                    addr,
		Log:                         log,
		Metrics:                     fm,
		Attestor:                    FakeAttestor{},
		Manager:                     FakeManager{},
		DefaultSVIDName:             "DefaultSVIDName",
		DefaultBundleName:           "DefaultBundleName",
		DefaultAllBundlesName:       "DefaultAllBundlesName",
		DisableSPIFFECertValidation: true,
		WorkloadAPIRateLimit: WorkloadAPIRateLimitConfig{
			FetchJWTSVID: 1,
		},
		newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return FakeWorkloadAPIServer{Attestor: c.Attestor.(PeerTrackerAttestor), RateLimiter: c.RateLimiter}
		},
		newSDSv3Server: func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return FakeSDSv3Server{Attestor: c.Attestor.(PeerTrackerAttestor)}
		},
		newHealthServer: func(c healthv1.Config) grpc_health_v1.HealthServer {
			return FakeHealthServer{}
		},
	})
	e.hooks.listening = make(chan struct{})

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.ListenAndServe(serveCtx)
	}()
	defer func() {
		serveCancel()
		assert.NoError(t, <-errCh)
	}()
	waitForListening(t, e, errCh)

	target, err := util.GetTargetName(e.addr)
	require.NoError(t, err)

	conn, err := util.NewGRPCClient(target)
	require.NoError(t, err)
	defer conn.Close()

	wlClient := workload_pb.NewSpiffeWorkloadAPIClient(conn)
	callCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

	// First call is within the burst of 1 and must succeed.
	_, err = wlClient.FetchJWTSVID(callCtx, &workload_pb.JWTSVIDRequest{})
	require.NoError(t, err)

	// Second call exhausts the burst and must be rejected.
	_, err = wlClient.FetchJWTSVID(callCtx, &workload_pb.JWTSVIDRequest{})
	spiretest.AssertGRPCStatusContains(t, err, codes.Unavailable, "rate limit exceeded")

	// Verify the rate_limit_exceeded metric was emitted for the rejected call.
	found := false
	for _, item := range fm.AllMetrics() {
		if item.Type == fakemetrics.IncrCounterWithLabelsType &&
			len(item.Key) == 2 && item.Key[0] == "workload_api" && item.Key[1] == "rate_limit_exceeded" {
			found = true
			break
		}
	}
	assert.True(t, found, "rate_limit_exceeded metric should be emitted on rejection")
}

// TestEndpointsSDSv3RateLimitIntegration verifies that the rate limiter is
// wired through the full Endpoints → sdsv3.Config path.
func TestEndpointsSDSv3RateLimitIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	log, _ := test.NewNullLogger()
	fm := fakemetrics.New()
	addr := getTestAddr(t)

	e := New(Config{
		BindAddr:                    addr,
		Log:                         log,
		Metrics:                     fm,
		Attestor:                    FakeAttestor{},
		Manager:                     FakeManager{},
		DefaultSVIDName:             "DefaultSVIDName",
		DefaultBundleName:           "DefaultBundleName",
		DefaultAllBundlesName:       "DefaultAllBundlesName",
		DisableSPIFFECertValidation: true,
		WorkloadAPIRateLimit: WorkloadAPIRateLimitConfig{
			FetchSecrets: 1,
		},
		newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return FakeWorkloadAPIServer{Attestor: c.Attestor.(PeerTrackerAttestor)}
		},
		newSDSv3Server: func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return FakeSDSv3Server{Attestor: c.Attestor.(PeerTrackerAttestor), RateLimiter: c.RateLimiter}
		},
		newHealthServer: func(c healthv1.Config) grpc_health_v1.HealthServer {
			return FakeHealthServer{}
		},
	})
	e.hooks.listening = make(chan struct{})

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.ListenAndServe(serveCtx)
	}()
	defer func() {
		serveCancel()
		assert.NoError(t, <-errCh)
	}()
	waitForListening(t, e, errCh)

	target, err := util.GetTargetName(e.addr)
	require.NoError(t, err)

	conn, err := util.NewGRPCClient(target)
	require.NoError(t, err)
	defer conn.Close()

	sdsClient := secret_v3.NewSecretDiscoveryServiceClient(conn)
	callCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

	// First call is within the burst of 1 and must succeed.
	_, err = sdsClient.FetchSecrets(callCtx, &discovery_v3.DiscoveryRequest{})
	require.NoError(t, err)

	// Second call exhausts the burst and must be rejected.
	_, err = sdsClient.FetchSecrets(callCtx, &discovery_v3.DiscoveryRequest{})
	spiretest.AssertGRPCStatusContains(t, err, codes.Unavailable, "rate limit exceeded")
}
