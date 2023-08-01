package endpoints

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv2"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
				// Call counter
				{Type: fakemetrics.IncrCounterWithLabelsType, Key: []string{"rpc", "workload_api", "fetch_jwtsvid"}, Val: 1, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
				{Type: fakemetrics.MeasureSinceWithLabelsType, Key: []string{"rpc", "workload_api", "fetch_jwtsvid", "elapsed_time"}, Val: 0, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
			},
		},
		{
			name: "sds v2 api has peertracker attestor plumbed",
			do: func(t *testing.T, conn *grpc.ClientConn) {
				sdsClient := discovery_v2.NewSecretDiscoveryServiceClient(conn)
				_, err := sdsClient.FetchSecrets(ctx, &api_v2.DiscoveryRequest{})
				require.NoError(t, err)
			},
			expectedLogs: []spiretest.LogEntry{
				logEntryWithPID(logrus.InfoLevel, "Success",
					"method", "FetchSecrets",
					"service", "SDS.v2",
				),
			},
			expectedMetrics: []fakemetrics.MetricItem{
				// Global connection counter and then the increment/decrement of the connection gauge
				{Type: fakemetrics.IncrCounterType, Key: []string{"sds_api", "connection"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"sds_api", "connections"}, Val: 1},
				{Type: fakemetrics.SetGaugeType, Key: []string{"sds_api", "connections"}, Val: 0},
				// Call counter
				{Type: fakemetrics.IncrCounterWithLabelsType, Key: []string{"rpc", "sds", "v2", "fetch_secrets"}, Val: 1, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
				{Type: fakemetrics.MeasureSinceWithLabelsType, Key: []string{"rpc", "sds", "v2", "fetch_secrets", "elapsed_time"}, Val: 0, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
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
				// Call counter
				{Type: fakemetrics.IncrCounterWithLabelsType, Key: []string{"rpc", "sds", "v3", "fetch_secrets"}, Val: 1, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
				{Type: fakemetrics.MeasureSinceWithLabelsType, Key: []string{"rpc", "sds", "v3", "fetch_secrets", "elapsed_time"}, Val: 0, Labels: []metrics.Label{
					{Name: "status", Value: "OK"},
				}},
			},
		},
		{
			name:       "access denied to remote caller",
			fromRemote: true,
		},
	} {
		tt := tt
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
				EnableDeprecatedSDSv2API:    true,

				// Assert the provided config and return a fake Workload API server
				newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					if tt.expectClaims != nil {
						assert.Equal(t, tt.expectClaims, c.AllowedForeignJWTClaims)
					} else {
						assert.Empty(t, c.AllowedForeignJWTClaims)
					}
					return FakeWorkloadAPIServer{Attestor: attestor}
				},

				// Assert the provided config and return a fake SDS server
				newSDSv2Server: func(c sdsv2.Config) discovery_v2.SecretDiscoveryServiceServer {
					attestor, ok := c.Attestor.(PeerTrackerAttestor)
					require.True(t, ok, "attestor was not a PeerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					assert.Equal(t, "DefaultSVIDName", c.DefaultSVIDName)
					assert.Equal(t, "DefaultBundleName", c.DefaultBundleName)
					assert.True(t, c.Enabled)
					return FakeSDSv2Server{Attestor: attestor}
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
				testRemoteCaller(ctx, t, target)
				return
			}

			conn, err := util.GRPCDialContext(ctx, target, grpc.WithBlock())
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

type FakeManager struct {
	manager.Manager
}

type FakeWorkloadAPIServer struct {
	Attestor PeerTrackerAttestor
	*workload_pb.UnimplementedSpiffeWorkloadAPIServer
}

func (s FakeWorkloadAPIServer) FetchJWTSVID(ctx context.Context, _ *workload_pb.JWTSVIDRequest) (*workload_pb.JWTSVIDResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &workload_pb.JWTSVIDResponse{}, nil
}

type FakeSDSv2Server struct {
	Attestor PeerTrackerAttestor
	*discovery_v2.UnimplementedSecretDiscoveryServiceServer
}

func (s FakeSDSv2Server) FetchSecrets(ctx context.Context, _ *api_v2.DiscoveryRequest) (*api_v2.DiscoveryResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &api_v2.DiscoveryResponse{}, nil
}

type FakeSDSv3Server struct {
	Attestor PeerTrackerAttestor
	*secret_v3.UnimplementedSecretDiscoveryServiceServer
}

func (s FakeSDSv3Server) FetchSecrets(ctx context.Context, _ *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &discovery_v3.DiscoveryResponse{}, nil
}

type FakeHealthServer struct {
	*grpc_health_v1.UnimplementedHealthServer
}

func attest(ctx context.Context, attestor PeerTrackerAttestor) error {
	log := rpccontext.Logger(ctx)
	selectors, err := attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to attest")
		return err
	}
	if len(selectors) == 0 {
		log.Error("Permission denied")
		return status.Error(codes.PermissionDenied, "attestor did not return selectors")
	}
	log.Info("Success")
	return nil
}

func logEntryWithPID(level logrus.Level, msg string, keyvalues ...interface{}) spiretest.LogEntry {
	data := logrus.Fields{
		telemetry.PID: fmt.Sprint(os.Getpid()),
	}
	for i := 0; i < len(keyvalues); i += 2 {
		key := keyvalues[i]
		var value interface{}
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
