package health_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

func TestServiceCheck(t *testing.T) {
	ca := testca.New(t, td)
	x509SVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	bundle := ca.X509Bundle()

	for _, tt := range []struct {
		name                string
		wlapiCode           codes.Code
		service             string
		expectCode          codes.Code
		expectMsg           string
		expectServingStatus grpc_health_v1.HealthCheckResponse_ServingStatus
		expectLogs          []spiretest.LogEntry
	}{
		{
			name:                "success with OK",
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_SERVING,
		},
		{
			name:                "success with PermissionDenied",
			wlapiCode:           codes.PermissionDenied,
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_SERVING,
		},
		{
			name:                "failure with other status codes",
			wlapiCode:           codes.Unavailable,
			expectCode:          codes.OK,
			expectServingStatus: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Health check failed",
					Data: logrus.Fields{
						"error":  "rpc error: code = Unavailable desc = ",
						"reason": "unable to fetch X.509 context from Workload API",
					},
				},
			},
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, logHook := test.NewNullLogger()

			wlAPI := fakeWorkloadAPI{
				code:     tt.wlapiCode,
				x509SVID: x509SVID,
				bundle:   bundle,
			}

			service := health.New(health.Config{
				Addr: spiretest.StartWorkloadAPI(t, wlAPI),
			})

			server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
				health.RegisterService(s, service)
			},
				grpctest.OverrideContext(func(ctx context.Context) context.Context {
					return rpccontext.WithLogger(ctx, log)
				}),
			)

			client := grpc_health_v1.NewHealthClient(server.NewGRPCClient(t))
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

type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	x509SVID *x509svid.SVID
	bundle   *x509bundle.Bundle
	code     codes.Code
}

func (w fakeWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if w.code != codes.OK {
		return status.Error(w.code, "")
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(w.x509SVID.PrivateKey)
	if err != nil {
		return err
	}
	return stream.Send(&workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    w.x509SVID.ID.String(),
				X509Svid:    x509util.DERFromCertificates(w.x509SVID.Certificates),
				X509SvidKey: privateKey,
				Bundle:      x509util.DERFromCertificates(w.bundle.X509Authorities()),
			},
		},
	})
}
