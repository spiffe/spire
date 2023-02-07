package fakeworkloadapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type FakeRequest struct {
	Req  proto.Message
	Resp proto.Message
	Err  error
}

type WorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	addr net.Addr
	t    *testing.T

	ExpFetchJWTSVIDReq    *workload.JWTSVIDRequest
	ExpFetchJWTBundlesReq *workload.JWTBundlesRequest

	fetchX509SVIDRequest   FakeRequest
	fetchJWTSVIDRequest    FakeRequest
	fetchJWTBundlesRequest FakeRequest
	validateJWTRequest     FakeRequest
}

func New(t *testing.T, responses ...*FakeRequest) *WorkloadAPI {
	w := new(WorkloadAPI)
	w.t = t

	for _, response := range responses {
		if response == nil {
			continue
		}
		switch response.Resp.(type) {
		case *workload.X509SVIDResponse:
			w.fetchX509SVIDRequest = *response
		case *workload.JWTSVIDResponse:
			w.fetchJWTSVIDRequest = *response
		case *workload.JWTBundlesResponse:
			w.fetchJWTBundlesRequest = *response
		case *workload.ValidateJWTSVIDResponse:
			w.validateJWTRequest = *response
		default:
			require.FailNow(t, "unexpected result type %T", response.Resp)
		}
	}

	w.addr = spiretest.StartWorkloadAPI(t, w)

	return w
}

func (w *WorkloadAPI) Addr() net.Addr {
	return w.addr
}

func (w *WorkloadAPI) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkSecurityHeader(stream.Context()); err != nil {
		return err
	}

	if w.fetchX509SVIDRequest.Err != nil {
		return w.fetchX509SVIDRequest.Err
	}

	if request, ok := w.fetchX509SVIDRequest.Req.(*workload.X509SVIDRequest); ok {
		spiretest.AssertProtoEqual(w.t, request, req)
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchX509SVIDRequest.Req))
	}

	if response, ok := w.fetchX509SVIDRequest.Resp.(*workload.X509SVIDResponse); ok {
		_ = stream.Send(response)
		<-stream.Context().Done()
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchX509SVIDRequest.Resp))
	}

	return nil
}

func (w *WorkloadAPI) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if w.fetchJWTSVIDRequest.Err != nil {
		return nil, w.fetchJWTSVIDRequest.Err
	}
	if request, ok := w.fetchJWTSVIDRequest.Req.(*workload.JWTSVIDRequest); ok {
		spiretest.AssertProtoEqual(w.t, request, req)
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchJWTSVIDRequest.Req))
	}

	if response, ok := w.fetchJWTSVIDRequest.Resp.(*workload.JWTSVIDResponse); ok {
		return response, nil
	}
	require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchJWTSVIDRequest.Resp))
	return nil, nil
}

func (w *WorkloadAPI) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := checkSecurityHeader(stream.Context()); err != nil {
		return err
	}

	if w.fetchJWTBundlesRequest.Err != nil {
		return w.fetchJWTBundlesRequest.Err
	}

	if request, ok := w.fetchJWTBundlesRequest.Req.(*workload.JWTBundlesRequest); ok {
		spiretest.AssertProtoEqual(w.t, request, req)
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchJWTBundlesRequest.Req))
	}

	if response, ok := w.fetchJWTBundlesRequest.Resp.(*workload.JWTBundlesResponse); ok {
		_ = stream.Send(response)
		<-stream.Context().Done()
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.fetchJWTBundlesRequest.Resp))
	}
	return nil
}

func (w *WorkloadAPI) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if w.validateJWTRequest.Err != nil {
		return nil, w.validateJWTRequest.Err
	}
	if request, ok := w.validateJWTRequest.Req.(*workload.ValidateJWTSVIDRequest); ok {
		spiretest.AssertProtoEqual(w.t, request, req)
	} else {
		require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.validateJWTRequest.Req))
	}

	if response, ok := w.validateJWTRequest.Resp.(*workload.ValidateJWTSVIDResponse); ok {
		return response, nil
	}
	require.FailNow(w.t, fmt.Sprintf("unexpected message type %T", w.validateJWTRequest.Resp))
	return nil, nil
}

func checkSecurityHeader(ctx context.Context) error {
	// Ensure security header is sent
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return errors.New("request received without security header")
	}
	return nil
}
