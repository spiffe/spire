package fakeworkloadapi

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Result interface {
	result()
}

type fetchX509SVIDResult func(workload.SpiffeWorkloadAPI_FetchX509SVIDServer) (bool, error)

func (fn fetchX509SVIDResult) do(stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) (done bool, err error) {
	return fn(stream)
}

func (fn fetchX509SVIDResult) result() {}

func FetchX509SVIDErrorOnce(err error) Result {
	return fetchX509SVIDResult(func(workload.SpiffeWorkloadAPI_FetchX509SVIDServer) (bool, error) {
		return true, err
	})
}

func FetchX509SVIDErrorAlways(err error) Result {
	return fetchX509SVIDResult(func(workload.SpiffeWorkloadAPI_FetchX509SVIDServer) (bool, error) {
		return false, err
	})
}

func FetchX509SVIDResponses(responses ...*workload.X509SVIDResponse) Result {
	return fetchX509SVIDResult(func(stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) (bool, error) {
		for _, response := range responses {
			if err := stream.Send(response); err != nil {
				return true, err
			}
		}
		return true, nil
	})
}

type WorkloadAPI struct {
	dir    string
	addr   *net.UnixAddr
	server *grpc.Server

	mu                   sync.Mutex
	fetchX509SVIDResults []fetchX509SVIDResult
}

func New(t *testing.T, results ...Result) *WorkloadAPI {
	w := new(WorkloadAPI)

	for _, result := range results {
		switch result := result.(type) {
		case fetchX509SVIDResult:
			w.fetchX509SVIDResults = append(w.fetchX509SVIDResults, result)
		default:
			require.FailNow(t, "unexpected result type %T", result)
		}
	}

	var err error
	w.dir, err = ioutil.TempDir("", "api-workload-tests")
	if err != nil {
		w.Close()
		require.NoError(t, err)
	}
	w.addr = &net.UnixAddr{
		Net:  "unix",
		Name: filepath.Join(w.dir, "agent.sock"),
	}

	listener, err := net.Listen("unix", w.addr.Name)
	if err != nil {
		w.Close()
		require.NoError(t, err)
	}

	w.server = grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(w.server, w)
	go func() { _ = w.server.Serve(listener) }()
	return w
}

func (w *WorkloadAPI) Close() {
	if w.server != nil {
		w.server.Stop()
	}
	if w.dir != "" {
		os.RemoveAll(w.dir)
	}
}

func (w *WorkloadAPI) Addr() *net.UnixAddr {
	return w.addr
}

func (w *WorkloadAPI) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkSecurityHeader(stream.Context()); err != nil {
		return err
	}

	// service all of the results
	for {
		result := w.nextFetchX509SVIDResult()
		if result == nil {
			break
		}

		done, err := result.do(stream)
		if done {
			w.advanceFetchX509SVIDResult()
		}

		if err != nil {
			return err
		}
	}

	// wait for the context to be canceled
	<-stream.Context().Done()
	return nil
}

func (w *WorkloadAPI) FetchJWTSVID(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func (w *WorkloadAPI) FetchJWTBundles(*workload.JWTBundlesRequest, workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return errors.New("unimplemented")
}

func (w *WorkloadAPI) ValidateJWTSVID(context.Context, *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func (w *WorkloadAPI) nextFetchX509SVIDResult() fetchX509SVIDResult {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.fetchX509SVIDResults) == 0 {
		return nil
	}
	return w.fetchX509SVIDResults[0]
}

func (w *WorkloadAPI) advanceFetchX509SVIDResult() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.fetchX509SVIDResults) > 0 {
		w.fetchX509SVIDResults = w.fetchX509SVIDResults[1:]
	}
}

func checkSecurityHeader(ctx context.Context) error {
	// Ensure security header is sent
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return errors.New("request received without security header")
	}
	return nil
}
