package spireplugin

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"testing"
	"time"

	w_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
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
)

var (
	ctx         = context.Background()
	trustDomain = spiffeid.RequireTrustDomainFromString("example.com")
)

type handler struct {
	svid.SVIDServer
	bundle.BundleServer

	server *grpc.Server
	addr   string

	bundleMtx sync.RWMutex
	bundle    *types.Bundle

	ca   *testca.CA
	cert []*x509.Certificate
	key  crypto.Signer

	err error

	// Custom downstream response
	downstreamResponse *svid.NewDownstreamX509CAResponse
}

type whandler struct {
	w_pb.SpiffeWorkloadAPIServer

	socketPath string

	ca   *testca.CA
	cert []*x509.Certificate
	key  crypto.Signer

	svidCert []byte
	svidKey  []byte
}

type testHandler struct {
	wAPIServer *whandler
	sAPIServer *handler
}

func (h *testHandler) startTestServers(t *testing.T, ca *testca.CA, serverCert []*x509.Certificate, serverKey crypto.Signer,
	svidCert []byte, svidKey []byte) {
	h.wAPIServer = &whandler{cert: serverCert, key: serverKey, ca: ca, svidCert: svidCert, svidKey: svidKey}
	h.sAPIServer = &handler{cert: serverCert, key: serverKey, ca: ca}
	h.sAPIServer.startServerAPITestServer(t)
	h.wAPIServer.startWAPITestServer(t)
}

func (w *whandler) startWAPITestServer(t *testing.T) {
	w.socketPath = spiretest.StartWorkloadAPIOnTempSocket(t, w)
}

func (w *whandler) FetchX509SVID(_ *w_pb.X509SVIDRequest, stream w_pb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	svid := &w_pb.X509SVID{
		SpiffeId:    trustDomain.NewID("workload").String(),
		X509Svid:    w.svidCert,
		X509SvidKey: w.svidKey,
		Bundle:      w.cert[0].Raw,
	}

	resp := new(w_pb.X509SVIDResponse)
	resp.Svids = []*w_pb.X509SVID{}
	resp.Svids = append(resp.Svids, svid)

	err := stream.Send(resp)
	if err != nil {
		return err
	}
	return nil
}

func (h *handler) startServerAPITestServer(t *testing.T) {
	h.loadInitialBundle(t)

	creds := credentials.NewServerTLSFromCert(&tls.Certificate{
		Certificate: [][]byte{h.cert[0].Raw},
		PrivateKey:  h.key,
	})

	opts := grpc.Creds(creds)
	h.server = grpc.NewServer(opts)

	svid.RegisterSVIDServer(h.server, h)
	bundle.RegisterBundleServer(h.server, h)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = l.Addr().String()
	go func() { err := h.server.Serve(l); panic(err) }()
}

func (h *handler) loadInitialBundle(t *testing.T) {
	jwksBytes, err := ioutil.ReadFile("_test_data/keys/jwks.json")
	require.NoError(t, err)
	b, err := bundleutil.Unmarshal(trustDomain.IDString(), jwksBytes)
	require.NoError(t, err)

	// Append X509 authorities
	for _, rootCA := range h.ca.Bundle().X509Authorities() {
		b.AppendRootCA(rootCA)
	}

	// Parse common bundle into types
	p := b.Proto()
	var jwtAuthorities []*types.JWTKey
	for _, k := range p.JwtSigningKeys {
		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			PublicKey: k.PkixBytes,
			ExpiresAt: k.NotAfter,
			KeyId:     k.Kid,
		})
	}

	var x509Authorities []*types.X509Certificate
	for _, cert := range p.RootCas {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1: cert.DerBytes,
		})
	}

	h.setBundle(&types.Bundle{
		TrustDomain:     p.TrustDomainId,
		RefreshHint:     p.RefreshHint,
		JwtAuthorities:  jwtAuthorities,
		X509Authorities: x509Authorities,
	})
}

func (h *handler) appendKey(key *types.JWTKey) *types.Bundle {
	h.bundleMtx.Lock()
	defer h.bundleMtx.Unlock()
	h.bundle.JwtAuthorities = append(h.bundle.JwtAuthorities, key)
	return cloneBundle(h.bundle)
}

func (h *handler) appendRootCA(rootCA *types.X509Certificate) *types.Bundle {
	h.bundleMtx.Lock()
	defer h.bundleMtx.Unlock()
	h.bundle.X509Authorities = append(h.bundle.X509Authorities, rootCA)
	return cloneBundle(h.bundle)
}

func (h *handler) getBundle() *types.Bundle {
	h.bundleMtx.RLock()
	defer h.bundleMtx.RUnlock()
	return cloneBundle(h.bundle)
}

func (h *handler) setBundle(b *types.Bundle) {
	h.bundleMtx.Lock()
	defer h.bundleMtx.Unlock()
	h.bundle = b
}

func (h *handler) NewDownstreamX509CA(ctx context.Context, req *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	if h.err != nil {
		return nil, h.err
	}

	if h.downstreamResponse != nil {
		return h.downstreamResponse, nil
	}

	ca := x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(h.cert[0], h.key),
		trustDomain,
		x509svid.UpstreamCAOptions{})

	cert, err := ca.SignCSR(ctx, req.Csr, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to sign CSR: %v", err)
	}

	var bundles [][]byte
	for _, b := range h.ca.X509Authorities() {
		bundles = append(bundles, b.Raw)
	}

	return &svid.NewDownstreamX509CAResponse{
		CaCertChain:     [][]byte{cert.Raw},
		X509Authorities: bundles,
	}, nil
}

func (h *handler) GetBundle(context.Context, *bundle.GetBundleRequest) (*types.Bundle, error) {
	if h.err != nil {
		return nil, h.err
	}
	return h.getBundle(), nil
}

func (h *handler) PublishJWTAuthority(ctx context.Context, req *bundle.PublishJWTAuthorityRequest) (*bundle.PublishJWTAuthorityResponse, error) {
	if h.err != nil {
		return nil, h.err
	}

	b := h.appendKey(req.JwtAuthority)
	return &bundle.PublishJWTAuthorityResponse{
		JwtAuthorities: b.JwtAuthorities,
	}, nil
}

func TestSpirePlugin_Configure(t *testing.T) {
	for _, tt := range []struct {
		name string
		req  *spi.ConfigureRequest
		err  string
	}{
		{
			name: "success",
			req: &spi.ConfigureRequest{
				Configuration: config,
				GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain.String()},
			},
		},
		{
			name: "malformed configuration",
			req: &spi.ConfigureRequest{
				Configuration: "{1}",
			},
			err: "expected: STRING got: NUMBER",
		},
		{
			name: "no global config",
			req: &spi.ConfigureRequest{
				Configuration: config,
			},
			err: "global configuration is required",
		},
		{
			name: "no trust domain",
			req: &spi.ConfigureRequest{
				Configuration: config,
				GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{},
			},
			err: "trust_domain is required",
		},
		{
			name: "malformed trust domain",
			req: &spi.ConfigureRequest{
				Configuration: config,
				GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "malformed td"},
			},
			err: "malformed trustdomain: spiffeid: unable to parse: parse \"spiffe://malformed td\": invalid character \" \" in host name",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			m := New()
			resp, err := m.Configure(ctx, tt.req)

			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.Equal(t, &spi.ConfigureResponse{}, resp)
		})
	}
}

func TestSpirePlugin_GetPluginInfo(t *testing.T) {
	m, _ := newWithDefault(t, "", "")

	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestSpirePlugin_MintX509CA(t *testing.T) {
	ca := testca.New(t, trustDomain)

	// Create SVID returned when fetching
	s := ca.CreateX509SVID(trustDomain.NewID("workload"))
	svidCert, svidKey, err := s.MarshalRaw()
	require.NoError(t, err)

	// Create sever's CA
	serverCert, serverKey := ca.CreateX509Certificate(testca.WithURIs(trustDomain.NewID("/spire/server").URL()))

	csr, pubKey, err := util.NewCSRTemplate(trustDomain.IDString())
	require.NoError(t, err)

	cases := []struct {
		name             string
		getCSR           func() ([]byte, crypto.PublicKey)
		expectedErr      string
		sAPIError        error
		downstreamResp   *svid.NewDownstreamX509CAResponse
		customSocketPath string
		customServerAddr string
	}{
		{
			name: "valid CSR",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
		},
		{
			name: "invalid socket path",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			customSocketPath: "malformed path",
			expectedErr:      "rpc error: code = Unknown desc = failed to start server client: unable to create X509Source:",
		},
		{
			name: "invalid server address",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			customServerAddr: "localhost",
			expectedErr:      `rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp :0`,
		},
		{
			name: "invalid scheme",
			getCSR: func() ([]byte, crypto.PublicKey) {
				csr, pubKey, err := util.NewCSRTemplate("invalid://localhost")
				require.NoError(t, err)
				return csr, pubKey
			},
			expectedErr: `rpc error: code = Unknown desc = unable to sign CSR: "invalid://localhost" is not a valid trust domain SPIFFE ID: invalid scheme`,
		},
		{
			name: "wrong trust domain",
			getCSR: func() ([]byte, crypto.PublicKey) {
				csr, pubKey, err := util.NewCSRTemplate("spiffe://not-trusted")
				require.NoError(t, err)
				return csr, pubKey
			},
			expectedErr: `rpc error: code = Unknown desc = unable to sign CSR: "spiffe://not-trusted" does not belong to trust domain "example.com"`,
		},
		{
			name: "invalid CSR",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return []byte("invalid-csr"), nil
			},
			expectedErr: `rpc error: code = Unknown desc = unable to sign CSR: unable to parse CSR`,
		},
		{
			name: "failed to call server",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			sAPIError:   errors.New("some error"),
			expectedErr: "rpc error: code = Unknown desc = some error",
		},
		{
			name: "downstream returns malformed X509 authorities",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			downstreamResp: &svid.NewDownstreamX509CAResponse{
				X509Authorities: [][]byte{[]byte("malformed")},
			},
			expectedErr: "rpc error: code = Unknown desc = unable to parse X509 authorities: asn1: structure error",
		},
		{
			name: "downstream returns malformed CA chain",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			downstreamResp: &svid.NewDownstreamX509CAResponse{
				CaCertChain: [][]byte{[]byte("malformed")},
			},
			expectedErr: "rpc error: code = Unknown desc = unable to parse CA cert chain: asn1: structure error",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Setup servers
			server := testHandler{}
			server.startTestServers(t, ca, serverCert, serverKey, svidCert, svidKey)
			server.sAPIServer.err = c.sAPIError
			server.sAPIServer.downstreamResponse = c.downstreamResp

			serverAddr := server.sAPIServer.addr
			socketPath := server.wAPIServer.socketPath
			if c.customServerAddr != "" {
				serverAddr = c.customServerAddr
			}
			if c.customSocketPath != "" {
				socketPath = c.customSocketPath
			}

			p, mockClock := newWithDefault(t, serverAddr, socketPath)

			// Send initial request and get stream
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			csr, pubKey := c.getCSR()
			stream, err := p.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{Csr: csr})
			require.NoError(t, err)
			require.NotNil(t, stream)

			// Get first response
			firstResp, err := stream.Recv()
			if c.expectedErr != "" {
				require.Nil(t, firstResp)
				require.Contains(t, err.Error(), c.expectedErr)
				cancel()
				return
			}

			require.NoError(t, err)
			require.Len(t, firstResp.UpstreamX509Roots, 1)
			certs, err := x509util.RawCertsToCertificates(firstResp.X509CaChain)
			require.NoError(t, err)

			isEqual, err := cryptoutil.PublicKeyEqual(certs[0].PublicKey, pubKey)
			require.NoError(t, err)
			require.True(t, isEqual)

			// Update bundle to trigger another response. Move time forward at
			// the upstream poll frequency twice to ensure the plugin picks up
			// the change to the bundle.
			server.sAPIServer.appendRootCA(&types.X509Certificate{Asn1: []byte("new-root-bytes")})
			mockClock.Add(upstreamPollFreq)
			mockClock.Add(upstreamPollFreq)
			mockClock.Add(internalPollFreq)

			// Get bundle update
			bundleUpdateResp, err := stream.Recv()
			require.NoError(t, err)
			require.Len(t, bundleUpdateResp.UpstreamX509Roots, 2)
			require.Equal(t, bundleUpdateResp.UpstreamX509Roots[1], []byte("new-root-bytes"))
			require.Nil(t, bundleUpdateResp.X509CaChain)

			// Cancel ctx to stop getting updates
			cancel()

			// Verify stream is closed
			resp, err := stream.Recv()
			require.Contains(t, err.Error(), "rpc error: code = Canceled desc = context canceled")
			require.Nil(t, resp)
		})
	}
}

func TestSpirePlugin_PublishJWTKey(t *testing.T) {
	ca := testca.New(t, trustDomain)
	serverCert, serverKey := ca.CreateX509Certificate(testca.WithURIs(trustDomain.NewID("/spire/server").URL()))
	s := ca.CreateX509SVID(trustDomain.NewID("workload"))
	svidCert, svidKey, err := s.MarshalRaw()
	require.NoError(t, err)

	// Setup servers
	server := testHandler{}
	server.startTestServers(t, ca, serverCert, serverKey, svidCert, svidKey)
	p, mockClock := newWithDefault(t, server.sAPIServer.addr, server.wAPIServer.socketPath)

	// Send initial request and get stream
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := p.PublishJWTKey(ctx, &upstreamauthority.PublishJWTKeyRequest{
		JwtKey: &common.PublicKey{
			Kid: "kid-2",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, stream)

	// Get first response
	firstResp, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, firstResp)
	require.Len(t, firstResp.UpstreamJwtKeys, 3)
	assert.Equal(t, firstResp.UpstreamJwtKeys[0].Kid, "C6vs25welZOx6WksNYfbMfiw9l96pMnD")
	assert.Equal(t, firstResp.UpstreamJwtKeys[1].Kid, "gHTCunJbefYtnZnTctd84xeRWyMrEsWD")
	assert.Equal(t, firstResp.UpstreamJwtKeys[2].Kid, "kid-2")

	// Update bundle to trigger another response. Move time forward at the
	// upstream poll frequency twice to ensure the plugin picks up the change
	// to the bundle.
	server.sAPIServer.appendKey(&types.JWTKey{KeyId: "kid-3"})
	mockClock.Add(upstreamPollFreq)
	mockClock.Add(upstreamPollFreq)
	mockClock.Add(internalPollFreq)

	// Get bundle update
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, resp.UpstreamJwtKeys, 4)
	require.Equal(t, resp.UpstreamJwtKeys[3].Kid, "kid-3")

	// Cancel ctx to stop getting updates
	cancel()

	// Verify stream is closed
	resp, err = stream.Recv()
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "rpc error: code = Canceled desc = context canceled")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.sAPIServer.err = errors.New("some error")
	stream, err = p.PublishJWTKey(ctx, &upstreamauthority.PublishJWTKeyRequest{
		JwtKey: &common.PublicKey{
			Kid: "kid-2",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, stream)

	resp, err = stream.Recv()
	require.Nil(t, resp)
	require.EqualError(t, err, "rpc error: code = Unknown desc = some error")
}

func newWithDefault(t *testing.T, addr string, socketPath string) (upstreamauthority.Plugin, *clock.Mock) {
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
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain.String()},
	}

	var plugin upstreamauthority.Plugin
	spiretest.LoadPlugin(t, BuiltIn(), &plugin)
	if _, err = plugin.Configure(ctx, pluginConfig); err != nil {
		require.NoError(t, err)
	}

	mockClock := clock.NewMock(t)

	clk = mockClock

	return plugin, mockClock
}
