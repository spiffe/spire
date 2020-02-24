package spireplugin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	w_pb "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/api/node"
	node_pb "github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	config = `{
	"ttl":"1h",
	"server_address":"_test_data/keys/private_key.pem",
	"server_port":"_test_data/keys/cert.pem",
	"server_agent_address":"8090"
}`
	trustDomain        = "example.com"
	keyFilePath        = "_test_data/keys/private_key.pem"
	certFilePath       = "_test_data/keys/cert.pem"
	serverCertFilePath = "_test_data/keys/server.pem"
)

var (
	ctx = context.Background()
)

type handler struct {
	server *grpc.Server
	addr   string
}

type whandler struct {
	dir        string
	socketPath string
	server     *grpc.Server
}

type testHandler struct {
	wapiServer *whandler
	napiServer *handler
}

func (h *testHandler) startTestServers(t *testing.T) {
	h.wapiServer = &whandler{}
	h.napiServer = &handler{}
	h.napiServer.startNodeAPITestServer(t)
	h.wapiServer.startWAPITestServer(t)
}

func (h *testHandler) stopTestServers() {
	h.napiServer.server.Stop()
	os.RemoveAll(h.wapiServer.dir)
}

func (w *whandler) startWAPITestServer(t *testing.T) {
	dir, err := ioutil.TempDir("", "upstreamca-spire-test-")
	require.NoError(t, err)
	w.dir = dir
	w.socketPath = filepath.Join(dir, "test.sock")

	w.server = grpc.NewServer()

	w_pb.RegisterSpiffeWorkloadAPIServer(w.server, w)

	l, err := net.Listen("unix", w.socketPath)
	require.NoError(t, err)

	go func() { _ = w.server.Serve(l) }()
}

func (w *whandler) FetchX509SVID(_ *w_pb.X509SVIDRequest, stream w_pb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	keyPEM, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		fmt.Println("error" + err.Error())
		return nil
	}
	keyblock, rest := pem.Decode(keyPEM)

	if keyblock == nil {
		return errors.New("error : invalid key format")
	}

	if len(rest) > 0 {
		return errors.New("error : invalid key format - too many keys")
	}

	certPEM, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return errors.New("error : unable to read cert file")
	}

	block, rest := pem.Decode(certPEM)
	if block == nil {
		return errors.New("error : invalid cert format")
	}
	if len(rest) > 0 {
		return errors.New("error : invalid key format - too many certs")
	}

	svid := &w_pb.X509SVID{
		SpiffeId:    "spiffe://localhost/workload",
		X509Svid:    block.Bytes,
		X509SvidKey: keyblock.Bytes,
		Bundle:      block.Bytes,
	}

	resp := new(w_pb.X509SVIDResponse)
	resp.Svids = []*w_pb.X509SVID{}
	resp.Svids = append(resp.Svids, svid)

	err = stream.Send(resp)
	if err != nil {
		return err
	}
	return nil
}

func (w *whandler) ValidateJWTSVID(ctx context.Context, req *w_pb.ValidateJWTSVIDRequest) (*w_pb.ValidateJWTSVIDResponse, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (w *whandler) FetchJWTSVID(ctx context.Context, req *w_pb.JWTSVIDRequest) (*w_pb.JWTSVIDResponse, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (w *whandler) FetchJWTBundles(req *w_pb.JWTBundlesRequest, stream w_pb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return errors.New("NOT IMPLEMENTED")
}

func (h *handler) startNodeAPITestServer(t *testing.T) {
	creds, err := credentials.NewServerTLSFromFile(serverCertFilePath, keyFilePath)
	require.NoError(t, err)

	opts := grpc.Creds(creds)
	h.server = grpc.NewServer(opts)

	node_pb.RegisterNodeServer(h.server, h)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = l.Addr().String()
	go func() { _ = h.server.Serve(l) }()
}

func (h *handler) FetchX509SVID(server node_pb.Node_FetchX509SVIDServer) error {
	return errors.New("NOT IMPLEMENTED")
}

func (h *handler) FetchX509CASVID(ctx context.Context, req *node.FetchX509CASVIDRequest) (*node.FetchX509CASVIDResponse, error) {
	caKey, err := pemutil.LoadPrivateKey(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load test CA key")
	}

	caCert, err := pemutil.LoadCertificate(certFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load test CA certificate")
	}

	// configure upstream ca
	ca := x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, caKey),
		"localhost",
		x509svid.UpstreamCAOptions{
			TTL: 30 * time.Minute,
		})

	cert, err := ca.SignCSR(ctx, req.Csr, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to sign CSR: %v", err)
	}

	return &node.FetchX509CASVIDResponse{
		Svid: &node_pb.X509SVID{
			CertChain: cert.Raw,
			ExpiresAt: cert.NotAfter.Unix(),
		},
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://localhost",
			RootCas: []*common.Certificate{
				{DerBytes: cert.Raw},
			},
		},
	}, nil
}

func (h *handler) FetchJWTSVID(ctx context.Context, req *node_pb.FetchJWTSVIDRequest) (*node_pb.FetchJWTSVIDResponse, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (h *handler) Attest(stream node_pb.Node_AttestServer) (err error) {
	return errors.New("NOT IMPLEMENTED")
}

func TestSpirePlugin_Configure(t *testing.T) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain},
	}

	m := New()
	resp, err := m.Configure(ctx, pluginConfig)
	require.NoError(t, err)
	require.Equal(t, &spi.ConfigureResponse{}, resp)
}

func TestSpirePlugin_GetPluginInfo(t *testing.T) {
	m, done := newWithDefault(t, "", "")
	defer done()

	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestSpirePlugin_SubmitValidCSR(t *testing.T) {
	server := testHandler{}
	server.startTestServers(t)
	defer server.stopTestServers()

	m, done := newWithDefault(t, server.napiServer.addr, server.wapiServer.socketPath)
	defer done()

	validSpiffeID := "spiffe://localhost"
	csr, pubKey, err := util.NewCSRTemplate(validSpiffeID)
	require.NoError(t, err)

	resp, err := m.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{Csr: csr})
	require.NoError(t, err)
	require.NotNil(t, resp)

	certs, err := rawCertsToCerts(resp.X509CaChain)
	require.NoError(t, err)

	isEqual, err := cryptoutil.PublicKeyEqual(certs[0].PublicKey, pubKey)
	require.NoError(t, err)
	require.True(t, isEqual)
}

func TestSpirePlugin_SubmitInvalidCSR(t *testing.T) {
	server := testHandler{}
	server.startTestServers(t)
	defer server.stopTestServers()

	m, done := newWithDefault(t, server.napiServer.addr, server.wapiServer.socketPath)
	defer done()

	invalidSpiffeIDs := []string{"invalid://localhost", "spiffe://not-trusted"}
	for _, invalidSpiffeID := range invalidSpiffeIDs {
		csr, _, err := util.NewCSRTemplate(invalidSpiffeID)
		require.NoError(t, err)

		resp, err := m.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{Csr: csr})
		require.Error(t, err)
		require.Nil(t, resp)
	}

	invalidSequenceOfBytesAsCSR := []byte("invalid-csr")
	resp, err := m.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{Csr: invalidSequenceOfBytesAsCSR})
	require.Error(t, err)
	require.Nil(t, resp)
}

func newWithDefault(t *testing.T, addr string, socketPath string) (upstreamauthority.Plugin, func()) {
	host, port, _ := net.SplitHostPort(addr)

	config := Configuration{
		ServerAddr:        host,
		ServerPort:        port,
		WorkloadAPISocket: socketPath,
	}

	jsonConfig, err := json.Marshal(config)
	require.NoError(t, err)

	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	var plugin upstreamauthority.Plugin
	done := spiretest.LoadPlugin(t, BuiltIn(), &plugin)
	if _, err = plugin.Configure(ctx, pluginConfig); err != nil {
		done()
		require.NoError(t, err)
	}
	return plugin, done
}

// rawCertsToCerts
func rawCertsToCerts(rawCerts [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	return certs, nil
}
