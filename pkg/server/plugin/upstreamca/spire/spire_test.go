package spireplugin

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/x509"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	node_pb "github.com/spiffe/spire/proto/api/node"
	w_pb "github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
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
	trustDomain           = "example.com"
	key_file_path         = "_test_data/keys/private_key.pem"
	cert_file_path        = "_test_data/keys/cert.pem"
	server_cert_file_path = "_test_data/keys/server.pem"
)

var (
	ctx = context.Background()
)

type handler struct {
	server *grpc.Server
}

type whandler struct {
	server *grpc.Server
}

type testHandler struct {
	wapiServer *whandler
	napiServer *handler
}

func (t *testHandler) startTestServers() {
	t.wapiServer = &whandler{}
	t.napiServer = &handler{}
	t.napiServer.startNodeAPITestServer()
	t.wapiServer.startWAPITestServer()
}

func (t *testHandler) stopTestServers() {
	t.napiServer.server.Stop()
}

func (w *whandler) startWAPITestServer() error {
	w.server = grpc.NewServer(grpc.Creds(auth.NewCredentials()))

	w_pb.RegisterSpiffeWorkloadAPIServer(w.server, w)

	os.Remove("./test.sock")

	l, err := net.Listen("unix", "./test.sock")
	if err != nil {
		fmt.Println("error" + err.Error())
		return nil
	}

	go func() { w.server.Serve(l) }()

	return nil
}

func (w *whandler) FetchX509SVID(_ *w_pb.X509SVIDRequest, stream w_pb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	keyPEM, err := ioutil.ReadFile(key_file_path)
	if err != nil {
		fmt.Println("error" + err.Error())
		return nil
	}
	keyblock, rest := pem.Decode(keyPEM)

	if keyblock == nil {
		fmt.Println("error : invalid key format")
		return nil
	}

	if len(rest) > 0 {
		fmt.Println("error : invalid key format - too many keys")
		return nil
	}

	certPEM, err := ioutil.ReadFile(cert_file_path)
	if err != nil {
		fmt.Println("error : unable to read cert file")
		return nil
	}

	block, rest := pem.Decode(certPEM)
	if block == nil {
		fmt.Println("error : invalid cert format")
		return nil
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
		fmt.Println("error" + err.Error())
		return err
	}
	return nil
}

func (w *whandler) ValidateJWTSVID(ctx context.Context, req *w_pb.ValidateJWTSVIDRequest) (*w_pb.ValidateJWTSVIDResponse, error) {
	return nil, nil
}

func (w *whandler) FetchJWTSVID(ctx context.Context, req *w_pb.JWTSVIDRequest) (*w_pb.JWTSVIDResponse, error) {
	return nil, nil
}

func (w *whandler) FetchJWTBundles(req *w_pb.JWTBundlesRequest, stream w_pb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return nil
}

func (h *handler) startNodeAPITestServer() error {
	creds, err := credentials.NewServerTLSFromFile(server_cert_file_path, key_file_path)
	if err != nil {
		fmt.Println("error + ", err.Error())
		return err
	}
	opts := grpc.Creds(creds)
	h.server = grpc.NewServer(opts)

	node_pb.RegisterNodeServer(h.server, h)

	err = h.runGRPCServer(ctx, h.server)
	if err != nil {
		fmt.Println("error + ", err.Error())
		return err
	}
	return nil
}

// runGRPCServer will start the server and block until it exits or we are dying.
func (h *handler) runGRPCServer(ctx context.Context, server *grpc.Server) error {

	l, err := net.Listen("tcp", "127.0.0.1:8090")
	if err != nil {
		return err
	}

	// Skip use of tomb here so we don't pollute a clean shutdown with errors

	go func() { server.Serve(l) }()

	return nil
}

func (h *handler) FetchX509SVID(server node_pb.Node_FetchX509SVIDServer) error {

	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		ctx := server.Context()

		// read test certificate and key files
		keyPEM, err := ioutil.ReadFile(key_file_path)
		if err != nil {
			fmt.Println("error" + err.Error())
			return nil
		}

		block, rest := pem.Decode(keyPEM)

		if block == nil {
			fmt.Println("error : invalid key format")
			return nil
		}

		if len(rest) > 0 {
			fmt.Println("error : invalid key format - too many keys")
			return nil
		}

		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("error" + err.Error())
			return nil
		}

		certPEM, err := ioutil.ReadFile(cert_file_path)
		if err != nil {
			fmt.Println("error : unable to read cert file")
			return nil
		}

		block, rest = pem.Decode(certPEM)

		if block == nil {
			fmt.Println("error : invalid cert format")
			return nil
		}

		if len(rest) > 0 {
			fmt.Println("error : invalid cert format : too many certs")
			return nil
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("error" + err.Error())
			return nil
		}

		// configure upstream ca
		ca := x509svid.NewUpstreamCA(
			x509util.NewMemoryKeypair(cert, key),
			"localhost",
			x509svid.UpstreamCAOptions{
				SerialNumber: x509util.NewSerialNumber(),
				TTL:          30 * time.Minute,
			})
		csr := request.Csrs[0]
		cert, err = ca.SignCSR(ctx, csr)
		if err != nil {
			fmt.Println("error " + err.Error())
			return nil
		}

		svids := make(map[string]*node_pb.X509SVID, 1)
		svid := &node_pb.X509SVID{
			CertChain: cert.Raw,
			ExpiresAt: cert.NotAfter.Unix(),
		}
		svids["spiffe://localhost"] = svid

		var rootCAs []*common.Certificate
		certificate := &common.Certificate{
			DerBytes: cert.Raw,
		}
		rootCAs = append(rootCAs, certificate)

		bundles := make(map[string]*common.Bundle, 1)
		bundle := &common.Bundle{
			TrustDomainId: "spiffe://localhost",
			RootCas:       rootCAs,
		}
		bundles["spiffe://localhost"] = bundle
		err = server.Send(&node_pb.FetchX509SVIDResponse{
			SvidUpdate: &node_pb.X509SVIDUpdate{
				Svids:   svids,
				Bundles: bundles,
			},
		})
		if err != nil {
			fmt.Errorf("Error sending FetchX509SVIDResponse: %v", err)
		}
	}

	return nil
}

func (h *handler) FetchJWTSVID(ctx context.Context, req *node_pb.FetchJWTSVIDRequest) (*node_pb.FetchJWTSVIDResponse, error) {
	return nil, nil
}

func (h *handler) Attest(stream node_pb.Node_AttestServer) (err error) {
	return nil
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
	m, err := newWithDefault()
	require.NoError(t, err)
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestSpirePlugin_SubmitValidCSR(t *testing.T) {
	server := testHandler{}
	server.startTestServers()
	defer server.stopTestServers()

	m, err := newWithDefault()

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		require.Len(t, rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.NoError(t, err)
		require.NotNil(t, resp)
	}
}

func TestSpirePlugin_SubmitInvalidCSR(t *testing.T) {
	server := testHandler{}
	server.startTestServers()
	defer server.stopTestServers()

	m, err := newWithDefault()

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		require.Len(t, rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.Error(t, err)
		require.Nil(t, resp)
	}
}

func newWithDefault() (upstreamca.Plugin, error) {
	config := Configuration{
		ServerAddr:        "127.0.0.1",
		ServerPort:        "8090",
		WorkloadAPISocket: "./test.sock",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	m := New()
	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}
