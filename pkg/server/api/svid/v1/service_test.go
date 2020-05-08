package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

func TestServiceMintX509SVID(t *testing.T) {
	// Add logger to context
	clock := clock.NewMock(t)
	log, _ := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)

	spiffeID := spiffeid.Must("trust.domain", "workload1")
	dns := []string{"dns1", "dns2"}
	ttl := time.Minute

	// Create Service
	trustDomain := spiffeid.RequireTrustDomainFromString("trust.domain")
	fakeServerCA := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{Clock: clock})
	service := svid.New(&svid.Config{
		ServerCA:    fakeServerCA,
		TrustDomain: trustDomain,
	})

	// Create certificate request
	key := testkey.NewEC256(t)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID.URL()},
		DNSNames:           dns,
		Subject: pkix.Name{
			Country:      []string{"US", "EN"},
			Organization: []string{"ORG"},
		},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// Parse raw certificate
	csr, err := x509.ParseCertificateRequest(csrRaw)
	require.NoError(t, err)

	// Mint CSR
	resp, err := service.MintX509SVID(ctx, csr, ttl)
	require.NoError(t, err)
	require.NotNil(t, resp)

	now := fakeServerCA.Clock().Now().UTC().Truncate(time.Second)
	expectedExpiredAt := now.Add(ttl)

	// Verify Response
	require.Equal(t, spiffeID, resp.ID)
	require.Equal(t, expectedExpiredAt, resp.ExpiresAt)

	// Verify Certificate
	svid := resp.CertChain[0]
	require.NoError(t, err)

	require.Equal(t, []*url.URL{spiffeID.URL()}, svid.URIs)
	require.Equal(t, expectedExpiredAt, svid.NotAfter)
	require.Equal(t, []string{"dns1", "dns2"}, svid.DNSNames)
	require.Equal(t, "dns1", svid.Subject.CommonName)
	require.Equal(t, "CN=dns1,O=ORG,C=US+C=EN", svid.Subject.String())
}
