package endpoints

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
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
		do              func(t *testing.T, conn *grpc.ClientConn)
		expectedLogs    []spiretest.LogEntry
		expectedMetrics []fakemetrics.MetricItem
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
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			udsPath := filepath.Join(spiretest.TempDir(t), "agent.sock")

			log, hook := test.NewNullLogger()
			metrics := fakemetrics.New()

			endpoints := New(Config{
				BindAddr: &net.UnixAddr{
					Net:  "unix",
					Name: udsPath,
				},
				Log:               log,
				Metrics:           metrics,
				Attestor:          FakeAttestor{},
				Manager:           FakeManager{},
				DefaultSVIDName:   "DefaultSVIDName",
				DefaultBundleName: "DefaultBundleName",

				// Assert the provided config and return a fake Workload API server
				newWorkloadAPIServer: func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
					attestor, ok := c.Attestor.(peerTrackerAttestor)
					require.True(t, ok, "attestor was not a peerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					return FakeWorkloadAPIServer{Attestor: attestor}
				},

				// Assert the provided config and return a fake SDS server
				newSDSv2Server: func(c sdsv2.Config) discovery_v2.SecretDiscoveryServiceServer {
					attestor, ok := c.Attestor.(peerTrackerAttestor)
					require.True(t, ok, "attestor was not a peerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					assert.Equal(t, "DefaultSVIDName", c.DefaultSVIDName)
					assert.Equal(t, "DefaultBundleName", c.DefaultBundleName)
					return FakeSDSv2Server{Attestor: attestor}
				},

				// Assert the provided config and return a fake SDS server
				newSDSv3Server: func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
					attestor, ok := c.Attestor.(peerTrackerAttestor)
					require.True(t, ok, "attestor was not a peerTrackerAttestor wrapper")
					assert.Equal(t, FakeManager{}, c.Manager)
					assert.Equal(t, "DefaultSVIDName", c.DefaultSVIDName)
					assert.Equal(t, "DefaultBundleName", c.DefaultBundleName)
					return FakeSDSv3Server{Attestor: attestor}
				},

				// Assert the provided config and return a fake health server
				newHealthServer: func(c healthv1.Config) grpc_health_v1.HealthServer {
					assert.Equal(t, udsPath, c.SocketPath)
					return FakeHealthServer{}
				},
			})

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

			// Dial the endpoints server with custom connect params that reduce the
			// base backoff delay. Otherwise, if the dial happens before the endpoint
			// is being served, the test can wait for a second before retrying.
			connectParams := grpc.ConnectParams{
				Backoff: backoff.DefaultConfig,
			}
			connectParams.Backoff.BaseDelay = 5 * time.Millisecond
			conn, err := grpc.DialContext(ctx, "unix:///"+udsPath,
				grpc.WithReturnConnectionError(),
				grpc.WithConnectParams(connectParams),
				grpc.WithInsecure())
			require.NoError(t, err)
			defer conn.Close()

			tt.do(t, conn)

			spiretest.AssertLogs(t, hook.AllEntries(), append([]spiretest.LogEntry{
				{Level: logrus.InfoLevel, Message: "Starting Workload and SDS APIs"},
			}, tt.expectedLogs...))
			assert.Equal(t, tt.expectedMetrics, metrics.AllMetrics())
		})
	}
}

type FakeManager struct {
	manager.Manager
}

type FakeWorkloadAPIServer struct {
	Attestor peerTrackerAttestor
	*workload_pb.UnimplementedSpiffeWorkloadAPIServer
}

func (s FakeWorkloadAPIServer) FetchJWTSVID(ctx context.Context, in *workload_pb.JWTSVIDRequest) (*workload_pb.JWTSVIDResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &workload_pb.JWTSVIDResponse{}, nil
}

type FakeSDSv2Server struct {
	Attestor peerTrackerAttestor
	*discovery_v2.UnimplementedSecretDiscoveryServiceServer
}

func (s FakeSDSv2Server) FetchSecrets(ctx context.Context, in *api_v2.DiscoveryRequest) (*api_v2.DiscoveryResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &api_v2.DiscoveryResponse{}, nil
}

type FakeSDSv3Server struct {
	Attestor peerTrackerAttestor
	*secret_v3.UnimplementedSecretDiscoveryServiceServer
}

func (s FakeSDSv3Server) FetchSecrets(ctx context.Context, in *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	if err := attest(ctx, s.Attestor); err != nil {
		return nil, err
	}
	return &discovery_v3.DiscoveryResponse{}, nil
}

type FakeHealthServer struct {
	*grpc_health_v1.UnimplementedHealthServer
}

func attest(ctx context.Context, attestor peerTrackerAttestor) error {
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
