package agent

import (
	"net"
	"testing"

	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/test/spiretest"
)

func TestCheckHealth(t *testing.T) {
	for _, tt := range []struct {
		name               string
		disableWorkloadAPI bool
		started            bool
		setupBindAddress   func(t *testing.T) net.Addr
		expectReady        bool
		expectLive         bool
		expectErr          string
	}{
		{
			name:        "public endpoint disabled",
			started:     true,
			expectReady: true,
			expectLive:  true,
		},
		{
			name:               "workload API disabled with serving endpoint",
			disableWorkloadAPI: true,
			started:            true,
			setupBindAddress: func(t *testing.T) net.Addr {
				return spiretest.StartGRPCServer(t, func(s *grpc.Server) {})
			},
			expectReady: true,
			expectLive:  true,
		},
		{
			name:               "workload API disabled with unavailable endpoint",
			disableWorkloadAPI: true,
			started:            true,
			setupBindAddress: func(t *testing.T) net.Addr {
				return spiretest.StartWorkloadAPI(t, unavailableWorkloadAPI{})
			},
			expectReady: false,
			expectLive:  false,
			expectErr:   "workload api is unavailable",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				DisableWorkloadAPI: tt.disableWorkloadAPI,
			}
			if tt.setupBindAddress != nil {
				c.BindAddress = tt.setupBindAddress(t)
			}

			a := New(c)
			a.started = tt.started

			state := a.CheckHealth()
			require.NotNil(t, state.Started)
			require.Equal(t, tt.started, *state.Started)
			require.Equal(t, tt.expectReady, state.Ready)
			require.Equal(t, tt.expectLive, state.Live)

			if tt.expectErr == "" {
				return
			}
			require.Equal(t, agentHealthDetails{
				WorkloadAPIErr: tt.expectErr,
			}, state.ReadyDetails)
			require.Equal(t, agentHealthDetails{
				WorkloadAPIErr: tt.expectErr,
			}, state.LiveDetails)
		})
	}
}

type unavailableWorkloadAPI struct {
	workload_pb.UnimplementedSpiffeWorkloadAPIServer
}

func (unavailableWorkloadAPI) FetchX509Bundles(_ *workload_pb.X509BundlesRequest, _ workload_pb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	return status.Error(codes.Unavailable, "")
}
