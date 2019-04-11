package endpoints

import (
	"context"
	"net"
	"testing"

	api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	sds_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnknownServiceHandler(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer listener.Close()

	log, hook := test.NewNullLogger()

	server := grpc.NewServer(grpc.UnknownServiceHandler(UnknownServiceHandler(log)))
	go server.Serve(listener)
	defer server.Stop()

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	require.NoError(err)

	// Assert handler return something special for SDS and logs the first time.
	sdsClient := sds_v2.NewSecretDiscoveryServiceClient(conn)
	_, err = sdsClient.FetchSecrets(context.Background(), &api_v2.DiscoveryRequest{})
	s := status.Convert(err)
	assert.Equal(codes.Unimplemented, s.Code())
	assert.Equal("Envoy SDS support has not been enabled on the agent (see `enable_sds` configurable)", s.Message())
	entries := hook.AllEntries()
	if assert.Len(entries, 1, "the first SDS RPC should be logged") {
		assert.Equal("Incoming RPC for Envoy SDS but it is not enabled (via `enable_sds` configurable)", entries[0].Message)
	}
	hook.Reset()

	_, err = sdsClient.FetchSecrets(context.Background(), &api_v2.DiscoveryRequest{})
	s = status.Convert(err)
	assert.Equal(codes.Unimplemented, s.Code())
	assert.Equal("Envoy SDS support has not been enabled on the agent (see `enable_sds` configurable)", s.Message())
	assert.Len(hook.AllEntries(), 0, "the second SDS RPC should not be logged")

	// Assert handler returns generic message for non-SDS and does no logging
	workloadClient := workload.NewSpiffeWorkloadAPIClient(conn)
	_, err = workloadClient.FetchJWTSVID(context.Background(), &workload.JWTSVIDRequest{})
	s = status.Convert(err)
	assert.Equal(codes.Unimplemented, s.Code())
	assert.Equal("unknown method /SpiffeWorkloadAPI/FetchJWTSVID", s.Message())
	assert.Len(hook.AllEntries(), 0, "the Workload API RPC shouldn't be logged")
}
