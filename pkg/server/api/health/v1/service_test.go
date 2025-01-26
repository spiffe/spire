package health_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/server/api/health/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

func TestServiceCheck(t *testing.T) {
	for _, tt := range []struct {
		name                string
		bundle              *common.Bundle
		dsErr               error
		service             string
		expectCode          codes.Code
		expectMsg           string
		expectServingStatus grpc_health_v1.HealthCheckResponse_ServingStatus
		expectLogs          []spiretest.LogEntry
	}{
		{
			name:                "success",
			bundle:              &common.Bundle{TrustDomainId: td.IDString()},
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_SERVING,
		},
		{
			name:       "service name not supported",
			service:    "WHATEVER",
			expectCode: codes.InvalidArgument,
			expectMsg:  "per-service health is not supported",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: per-service health is not supported",
				},
			},
		},
		{
			name:                "unable to retrieve bundle",
			dsErr:               errors.New("ohno"),
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Health check failed",
					Data: logrus.Fields{
						"reason": "unable to fetch bundle",
						"error":  "ohno",
					},
				},
			},
		},
		{
			name:                "bundle is missing",
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Health check failed",
					Data: logrus.Fields{
						"reason": "bundle is missing",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, logHook := test.NewNullLogger()

			ds := fakedatastore.New(t)
			if tt.dsErr != nil {
				ds.SetNextError(tt.dsErr)
			}
			if tt.bundle != nil {
				_, err := ds.CreateBundle(context.Background(), tt.bundle)
				require.NoError(t, err)
			}

			service := health.New(health.Config{
				TrustDomain: td,
				DataStore:   ds,
			})

			server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
				health.RegisterService(s, service)
			},
				grpctest.OverrideContext(func(ctx context.Context) context.Context {
					return rpccontext.WithLogger(ctx, log)
				}),
			)

			conn := server.NewGRPCClient(t)

			client := grpc_health_v1.NewHealthClient(conn)
			resp, err := client.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{
				Service: tt.service,
			})

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)

			if err != nil {
				return
			}
			require.Equal(t, tt.expectServingStatus, resp.Status)
		})
	}
}
