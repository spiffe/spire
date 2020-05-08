package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestMintX509SVID(t *testing.T) {
	log, _ := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)

	fakeService := &FakeService{}
	client, done := createClient(ctx, t, fakeService)
	defer done()

	spiffeID := spiffeid.Must("trust.domain", "workload1")

	// Create certificate request
	key := testkey.NewEC256(t)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID.URL()},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// Setup fake
	expiresAt := time.Now()
	fakeService.svid = &api.X509SVID{
		ID:        spiffeID,
		CertChain: []*x509.Certificate{},
		ExpiresAt: expiresAt,
	}

	// Mint certificate request
	resp, err := client.MintX509SVID(ctx, &svidpb.MintX509SVIDRequest{
		Csr: csrRaw,
		Ttl: 10,
	})
	require.NoError(t, err)

	require.Equal(t, "trust.domain", resp.Svid.Id.TrustDomain)
	require.Equal(t, "/workload1", resp.Svid.Id.Path)
	require.Equal(t, expiresAt.UTC().Unix(), resp.Svid.ExpiresAt)
}

type FakeService struct {
	svid.Service

	svid *api.X509SVID
	err  error
}

func (s *FakeService) MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.svid, nil
}

func createClient(ctx context.Context, t *testing.T, fakeService *FakeService) (svidpb.SVIDClient, func()) {
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, fakeService)
	}

	contextFn := func(context.Context) context.Context {
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)

	return svidpb.NewSVIDClient(conn), done
}
