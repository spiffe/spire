package ca

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	testclock "github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

func TestValidateUpstreamX509CAWithExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := testclock.NewMockAt(t, now)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	rootNotAfter := now.Add(40 * time.Minute)
	root, rootKey := testca.CreateCACertificate(t, nil, nil,
		testca.WithLifetime(now.Add(-time.Minute), rootNotAfter),
		testca.WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	)
	local, localKey := testca.CreateCACertificate(t, root, rootKey,
		testca.WithLifetime(now.Add(-time.Minute), now.Add(time.Hour)),
		testca.WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		testca.WithID(trustDomain.ID()),
	)

	validator, err := credvalidator.New(credvalidator.Config{
		Clock:       clk,
		TrustDomain: trustDomain,
	})
	require.NoError(t, err)

	effectiveNotAfter, err := (&X509CAValidator{
		TrustDomain:   trustDomain,
		CredValidator: validator,
		Signer:        localKey,
		Clock:         clk,
	}).ValidateUpstreamX509CAWithExpiry([]*x509.Certificate{local}, []*x509.Certificate{root})
	require.NoError(t, err)
	require.Equal(t, root.NotAfter, effectiveNotAfter)
}

func TestValidateUpstreamX509CAWithExpiryUsesEarliestIntermediate(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := testclock.NewMockAt(t, now)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	root, rootKey := testca.CreateCACertificate(t, nil, nil,
		testca.WithLifetime(now.Add(-time.Minute), now.Add(2*time.Hour)),
		testca.WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	)
	upstreamIntermediate, upstreamIntermediateKey := testca.CreateCACertificate(t, root, rootKey,
		testca.WithLifetime(now.Add(-time.Minute), now.Add(40*time.Minute)),
		testca.WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	)
	local, localKey := testca.CreateCACertificate(t, upstreamIntermediate, upstreamIntermediateKey,
		testca.WithLifetime(now.Add(-time.Minute), now.Add(time.Hour)),
		testca.WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		testca.WithID(trustDomain.ID()),
	)

	validator, err := credvalidator.New(credvalidator.Config{
		Clock:       clk,
		TrustDomain: trustDomain,
	})
	require.NoError(t, err)

	effectiveNotAfter, err := (&X509CAValidator{
		TrustDomain:   trustDomain,
		CredValidator: validator,
		Signer:        localKey,
		Clock:         clk,
	}).ValidateUpstreamX509CAWithExpiry([]*x509.Certificate{local, upstreamIntermediate}, []*x509.Certificate{root})
	require.NoError(t, err)
	require.Equal(t, upstreamIntermediate.NotAfter, effectiveNotAfter)
}

func TestEffectiveChainExpirySelectsLongestValidPath(t *testing.T) {
	now := time.Now()
	chains := [][]*x509.Certificate{
		{
			{NotAfter: now.Add(30 * time.Minute)},
			{NotAfter: now.Add(20 * time.Minute)},
		},
		{
			{NotAfter: now.Add(30 * time.Minute)},
			{NotAfter: now.Add(25 * time.Minute)},
		},
	}

	require.Equal(t, now.Add(25*time.Minute), EffectiveX509ChainExpiry(chains))
}
