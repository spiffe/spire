package workload

import (
	"context"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/api/workload"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestClientStart(t *testing.T) {
	w := &testWatcher{}
	_, err := NewX509SVIDClient(w, WithAddr("notexists"))
	require.EqualError(t, err, `spiffe/workload: agent address "notexists" is not a unix address`)
}

func TestClientUpdate(t *testing.T) {
	stubAPI := newStubbedAPI(t)
	stubAPI.StartServer()
	defer stubAPI.Cleanup()

	w := newTestWatcher(t)
	c, err := NewX509SVIDClient(w, WithAddr("unix:///"+stubAPI.SocketPath))
	require.NoError(t, err)

	err = c.Start(context.Background())
	require.NoError(t, err)

	t.Run("connect and update", func(t *testing.T) {
		stubAPI.Handler.SendX509Response("spiffe://example.org/foo")
		stubAPI.Handler.WaitForCall()
		w.WaitForUpdates(1)

		assert.Len(t, w.Errors, 0)
		assert.Len(t, w.X509SVIDs, 1)
		assert.Equal(t, "spiffe://example.org/foo", w.X509SVIDs[0].Default().SPIFFEID)
		w.X509SVIDs = nil
	})

	t.Run("new update", func(t *testing.T) {
		stubAPI.Handler.SendX509Response("spiffe://example.org/bar")
		stubAPI.Handler.WaitForCall()
		w.WaitForUpdates(1)

		assert.Len(t, w.X509SVIDs, 1)
		assert.Equal(t, "spiffe://example.org/bar", w.X509SVIDs[0].Default().SPIFFEID)
		assert.Len(t, w.Errors, 0)
		w.X509SVIDs = nil
	})

	t.Run("server restart", func(t *testing.T) {
		stubAPI.StopServer()
		w.WaitForUpdates(1)
		assert.Len(t, w.Errors, 1)
		assert.Error(t, w.Errors[0])
		assert.Contains(t, w.Errors[0].Error(), "transport is closing")
		assert.Len(t, w.X509SVIDs, 0)
		w.Errors = nil

		stubAPI.StartServer()
	})

	t.Run("stop", func(t *testing.T) {
		err = c.Stop(context.Background())

		assert.NoError(t, err)
		assert.Len(t, w.X509SVIDs, 0)
		assert.Len(t, w.Errors, 0)
	})
}

func TestStartStop(t *testing.T) {
	stubAPI := newStubbedAPI(t)
	stubAPI.StartServer()
	defer stubAPI.Cleanup()

	w := newTestWatcher(t)
	c, err := NewX509SVIDClient(w, WithAddr("unix:///"+stubAPI.SocketPath))
	require.NoError(t, err)

	t.Run("stop before start", func(t *testing.T) {
		err := c.Stop(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "client hasn't started")
	})

	t.Run("start once", func(t *testing.T) {
		err := c.Start(context.Background())
		require.NoError(t, err)
	})

	t.Run("start twice", func(t *testing.T) {
		err := c.Start(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "client already started")
	})

	t.Run("stop", func(t *testing.T) {
		err := c.Stop(context.Background())
		require.NoError(t, err)
	})

	t.Run("stop twice", func(t *testing.T) {
		err := c.Stop(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "client is already stopped")
	})

	t.Run("start after stop", func(t *testing.T) {
		err := c.Start(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "client cannot start once stopped")
	})
}

type testWatcher struct {
	t            *testing.T
	X509SVIDs    []*X509SVIDs
	Errors       []error
	updateSignal chan struct{}
	n            int
	timeout      time.Duration
}

func newTestWatcher(t *testing.T) *testWatcher {
	return &testWatcher{
		t:            t,
		updateSignal: make(chan struct{}, 100),
		timeout:      10 * time.Second,
	}
}

func (w *testWatcher) UpdateX509SVIDs(u *X509SVIDs) {
	w.X509SVIDs = append(w.X509SVIDs, u)
	w.n++
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) OnError(err error) {
	w.Errors = append(w.Errors, err)
	w.n++
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) WaitForUpdates(expectedNumUpdates int) {
	numUpdates := 0
	for {
		select {
		case <-w.updateSignal:
			numUpdates++
		case <-time.After(w.timeout):
			require.Fail(w.t, "Timeout exceeding waiting for updates.")
		}
		if numUpdates == expectedNumUpdates {
			return
		}
	}
}

type stubbedAPI struct {
	T          *testing.T
	SocketPath string
	Handler    *mockHandler
	Server     *grpc.Server
}

func newStubbedAPI(t *testing.T) *stubbedAPI {
	dir, err := ioutil.TempDir("", "workload-test")
	require.NoError(t, err)

	return &stubbedAPI{
		T:          t,
		SocketPath: path.Join(dir, "workload_api.sock"),
	}
}

func (s *stubbedAPI) StartServer() {
	l, err := net.Listen("unix", s.SocketPath)
	require.NoError(s.T, err)

	server := grpc.NewServer()
	handler := &mockHandler{
		t:                s.T,
		done:             make(chan struct{}),
		fetchX509Waiter:  make(chan struct{}, 1),
		sendX509Response: make(chan string),
	}
	workload.RegisterSpiffeWorkloadAPIServer(server, handler)
	go func() { server.Serve(l) }()

	s.Server = server
	s.Handler = handler
	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
}

func (s *stubbedAPI) StopServer() {
	s.Server.Stop()
	s.Handler.Stop()
}

func (s *stubbedAPI) Cleanup() {
	s.Handler.Stop()
	s.Server.Stop()
	os.RemoveAll(path.Dir(s.SocketPath))
}

type mockHandler struct {
	t                *testing.T
	done             chan struct{}
	fetchX509Waiter  chan struct{}
	sendX509Response chan string
}

func (m *mockHandler) Stop() { close(m.done) }

func (m *mockHandler) SendX509Response(name string) {
	m.sendX509Response <- name
}

func (m *mockHandler) WaitForCall() {
	<-m.fetchX509Waiter
}

func (m *mockHandler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	m.t.Run("check security header", func(t *testing.T) {
		md, ok := metadata.FromIncomingContext(stream.Context())
		require.True(t, ok, "Request doesn't contain grpc metadata.")
		require.Len(t, md.Get("workload.spiffe.io"), 1)
		require.Equal(t, "true", md.Get("workload.spiffe.io")[0])
	})

	for {
		select {
		case name := <-m.sendX509Response:
			stream.Send(m.resp(name))
			m.fetchX509Waiter <- struct{}{}
		case <-m.done:
			return nil

		}
	}
}

func (m *mockHandler) resp(name string) *workload.X509SVIDResponse {
	svid, key, err := util.LoadSVIDFixture()
	require.NoError(m.t, err)
	ca, _, err := util.LoadCAFixture()
	require.NoError(m.t, err)

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(m.t, err)

	svidMsg := &workload.X509SVID{
		SpiffeId:    name,
		X509Svid:    svid.Raw,
		X509SvidKey: keyData,
		Bundle:      ca.Raw,
	}
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
	}
}

func (m *mockHandler) FetchJWTSVID(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func (m *mockHandler) FetchJWTBundles(*workload.JWTBundlesRequest, workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return errors.New("unimplemented")
}

func (m *mockHandler) ValidateJWTSVID(context.Context, *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func TestGetAgentAddress(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		require.Equal(t, "unix:///tmp/agent.sock", GetAgentAddress())
	})
	t.Run("env", func(t *testing.T) {
		os.Setenv(EnvVarAgentAddress, "/foo")
		defer os.Unsetenv(EnvVarAgentAddress)
		require.Equal(t, "/foo", GetAgentAddress())
	})
}
