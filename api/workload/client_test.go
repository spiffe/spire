package workload

import (
	"crypto/x509"
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
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
	config := &ClientConfig{
		Addr:        addr,
		FailOnError: true,
	}
	c := NewClient(config)

	// Test single update and clean shutdown
	handler.delay = 10 * time.Second
	errChan := make(chan error)
	go func() { errChan <- c.Start() }()
	updateChan := c.UpdateChan()
	select {
	case <-time.NewTicker(1 * time.Second).C:
		t.Error("did not receive update in time")
	case <-updateChan:
	}

	c.Shutdown()
	select {
	case <-time.NewTicker(1 * time.Millisecond).C:
		t.Error("shutdown timed out")
	case err := <-errChan:
		if err != nil {
			t.Errorf("wanted nil, got %v", err)
		}
	}

	// Test successive updates
	handler.delay = 100 * time.Millisecond
	c = NewClient(config)
	go func() { errChan <- c.Start() }()
	updateChan = c.UpdateChan()
	select {
	case <-time.NewTicker(1 * time.Second).C:
		t.Error("did not receive update in time")
	case u := <-updateChan:
		if !reflect.DeepEqual(u, handler.resp1()) {
			t.Errorf("want %v; got %v", handler.resp1(), u)
		}
	}

	select {
	case <-time.NewTicker(105 * time.Millisecond).C:
		t.Errorf("did not receive update in time")
	case <-updateChan:
	}

	select {
	case <-time.NewTicker(1 * time.Second).C:
		t.Error("update not received after server reconnect")
	case <-errChan:
		t.Error("failed to reconnect to server")
	case <-updateChan:
	}

	c.Shutdown()
	select {
	case <-time.NewTicker(1 * time.Millisecond).C:
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
	h := &mockHandler{t: t}
	workload.RegisterSpiffeWorkloadAPIServer(s, h)
	go func() { s.Serve(l) }()

	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
	return sockPath, s, h
}

type mockHandler struct {
	t *testing.T

	delay time.Duration
}

func (m *mockHandler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	// Ensure security header is sent
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		m.t.Error("request received without security header")
	}

	resp := m.resp1()
	stream.Send(resp)

	time.Sleep(m.delay)
	stream.Send(resp)
	return nil
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
