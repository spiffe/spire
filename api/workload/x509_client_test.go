package workload

import (
	"context"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/test/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestClient_StartAndStop(t *testing.T) {
	sockPath, grpcServer, handler := newStubbedAPI(t)
	defer grpcServer.Stop()
	defer os.RemoveAll(path.Dir(sockPath))

	addr := &net.UnixAddr{
		Net:  "unix",
		Name: sockPath,
	}
	config := &X509ClientConfig{
		Addr:    addr,
		Timeout: 5 * time.Second,
	}
	c := NewX509Client(config)

	// Current should return an error if there isn't an SVID yet
	_, err := c.CurrentSVID()
	if err == nil {
		t.Error("wanted error, got nil")
	}

	// Test single update and clean shutdown
	handler.setDelay(10 * time.Second)
	errChan := make(chan error)
	go func() { errChan <- c.Start() }()
	updateChan := c.UpdateChan()
	select {
	case <-time.NewTimer(1 * time.Second).C:
		t.Error("did not receive update in time")
	case <-updateChan:
	}

	c.Stop()
	select {
	case <-time.NewTimer(1 * time.Millisecond).C:
		t.Error("shutdown timed out")
	case err := <-errChan:
		if err != nil {
			t.Errorf("wanted nil, got %v", err)
		}
	}

	// Test successive updates
	handler.setDelay(100 * time.Millisecond)
	c = NewX509Client(config)
	go func() { errChan <- c.Start() }()
	updateChan = c.UpdateChan()
	select {
	case <-time.NewTimer(1 * time.Second).C:
		t.Error("did not receive update in time")
	case u := <-updateChan:
		if !reflect.DeepEqual(u, handler.resp1()) {
			t.Errorf("want %v; got %v", handler.resp1(), u)
		}
	}

	select {
	case <-time.NewTimer(1 * time.Second).C:
		t.Fatal("did not receive update in time")
	case u := <-updateChan:
		if !reflect.DeepEqual(u, handler.resp2()) {
			t.Errorf("want %v; got %v", handler.resp2(), u)
		}
	}

	select {
	case <-time.NewTimer(5 * time.Second).C:
		t.Error("update not received after server reconnect")
	case err := <-errChan:
		t.Fatalf("failed to reconnect to server: %v", err)
	case u := <-updateChan:
		if !reflect.DeepEqual(u, handler.resp1()) {
			t.Errorf("want %v; got %v", handler.resp1(), u)
		}
	}

	// Current should always return the latest SVID
	curr, err := c.CurrentSVID()
	if err != nil {
		t.Errorf("got error %v", err)
	}
	if !reflect.DeepEqual(curr, handler.resp1()) {
		t.Errorf("want %v; got %v", handler.resp1(), curr)
	}

	c.Stop()
	select {
	case <-time.NewTimer(1 * time.Second).C:
		t.Error("shutdown timed out")
	case err := <-errChan:
		if err != nil {
			t.Errorf("wanted nil, got %v", err)
		}
	}
}

func newStubbedAPI(t *testing.T) (string, *grpc.Server, *mockHandler) {
	dir, err := ioutil.TempDir("", "workload-test")
	if err != nil {
		t.Errorf("could not create temp dir: %v", err)
	}

	sockPath := path.Join(dir, "workload_api.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Errorf("create UDS listener: %s", err)
	}

	s := grpc.NewServer()
	h := &mockHandler{
		t:   t,
		mtx: new(sync.Mutex),
	}
	workload.RegisterSpiffeWorkloadAPIServer(s, h)
	go func() { s.Serve(l) }()

	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
	return sockPath, s, h
}

type mockHandler struct {
	t *testing.T

	// Make sure this mock passes race tests
	mtx *sync.Mutex

	delay time.Duration
}

func (m *mockHandler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	// Ensure security header is sent
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		m.t.Error("request received without security header")
	}

	stream.Send(m.resp1())

	m.mtx.Lock()
	delay := m.delay
	m.mtx.Unlock()

	time.Sleep(delay)
	stream.Send(m.resp2())
	return nil
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

func (m *mockHandler) resp1() *workload.X509SVIDResponse {
	svid, key, err := util.LoadSVIDFixture()
	if err != nil {
		m.t.Errorf("could not load svid fixture: %v", err)
	}
	ca, _, err := util.LoadCAFixture()
	if err != nil {
		m.t.Errorf("could not load ca fixture: %v", err)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		m.t.Errorf("could not marshal private key: %v", err)
	}

	svidMsg := &workload.X509SVID{
		SpiffeId:    "spiffe://example.org/foo",
		X509Svid:    svid.Raw,
		X509SvidKey: keyData,
		Bundle:      ca.Raw,
	}
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
	}
}

func (m *mockHandler) resp2() *workload.X509SVIDResponse {
	resp := m.resp1()
	resp.Svids[0].SpiffeId = "spiffe://example.org/bar"
	return resp
}

func (m *mockHandler) setDelay(delay time.Duration) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.delay = delay
}
