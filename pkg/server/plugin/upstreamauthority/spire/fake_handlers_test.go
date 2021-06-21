package spireplugin

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	w_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type handler struct {
	svidv1.SVIDServer
	bundlev1.BundleServer

	server *grpc.Server
	addr   string

	bundleMtx sync.RWMutex
	bundle    *types.Bundle

	ca   *testca.CA
	cert []*x509.Certificate
	key  crypto.Signer

	err error

	// Custom downstream response
	downstreamResponse *svidv1.NewDownstreamX509CAResponse
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

	svidv1.RegisterSVIDServer(h.server, h)
	bundlev1.RegisterBundleServer(h.server, h)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = l.Addr().String()
	go func() { err := h.server.Serve(l); panic(err) }()
}

func (h *handler) loadInitialBundle(t *testing.T) {
	jwksBytes, err := os.ReadFile("testdata/keys/jwks.json")
	require.NoError(t, err)
	b, err := bundleutil.Unmarshal(trustDomain, jwksBytes)
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

func (h *handler) NewDownstreamX509CA(ctx context.Context, req *svidv1.NewDownstreamX509CARequest) (*svidv1.NewDownstreamX509CAResponse, error) {
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
		return nil, fmt.Errorf("unable to sign CSR: %w", err)
	}

	var bundles [][]byte
	for _, b := range h.ca.X509Authorities() {
		bundles = append(bundles, b.Raw)
	}

	return &svidv1.NewDownstreamX509CAResponse{
		CaCertChain:     [][]byte{cert.Raw},
		X509Authorities: bundles,
	}, nil
}

func (h *handler) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	if h.err != nil {
		return nil, h.err
	}
	return h.getBundle(), nil
}

func (h *handler) PublishJWTAuthority(ctx context.Context, req *bundlev1.PublishJWTAuthorityRequest) (*bundlev1.PublishJWTAuthorityResponse, error) {
	if h.err != nil {
		return nil, h.err
	}

	b := h.appendKey(req.JwtAuthority)
	return &bundlev1.PublishJWTAuthorityResponse{
		JwtAuthorities: b.JwtAuthorities,
	}, nil
}

func cloneBundle(b *types.Bundle) *types.Bundle {
	return proto.Clone(b).(*types.Bundle)
}
