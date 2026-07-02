package x509util_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUnknownAuthority(t *testing.T) {
	t.Run("no error provided", func(t *testing.T) {
		require.False(t, x509util.IsUnknownAuthorityError(nil))
	})

	t.Run("unexpected error", func(t *testing.T) {
		require.False(t, x509util.IsUnknownAuthorityError(errors.New("oh no")))
	})

	t.Run("unknown authority err", func(t *testing.T) {
		// Create two bundles with same TD and an SVID that is signed by one of them
		ca := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
		ca2 := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
		svid := ca2.CreateX509SVID(spiffeid.RequireFromString("spiffe://test.td/w1"))

		// Verify must fail
		_, _, err := x509svid.Verify(svid.Certificates, ca.X509Bundle())
		require.Error(t, err)

		require.True(t, x509util.IsUnknownAuthorityError(err))
	})
}

func TestIsSignedByRoot(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca1 := testca.New(t, td)
	intermediate := ca1.ChildCA(testca.WithID(td.ID()))
	svid1 := intermediate.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1"))

	ca2 := testca.New(t, td)
	svid2 := ca2.CreateX509SVID(spiffeid.RequireFromPath(td, "/w2"))

	invalidCertificate := []*x509.Certificate{{Raw: []byte("invalid")}}

	testSignedByRoot := func(t *testing.T, chain []*x509.Certificate, rootCAs []*x509.Certificate, expect bool, expectError string) {
		isSigned, err := x509util.IsSignedByRoot(chain, rootCAs)
		if expect {
			assert.True(t, isSigned, "Expected chain to be signed by root")
		} else {
			assert.False(t, isSigned, "Expected chain NOT to be signed by root")
		}
		if expectError != "" {
			assert.ErrorContains(t, err, expectError)
		} else {
			assert.NoError(t, err)
		}
	}

	testSignedByRoot(t, svid1.Certificates, ca1.X509Authorities(), true, "")
	testSignedByRoot(t, svid2.Certificates, ca2.X509Authorities(), true, "")
	testSignedByRoot(t, svid2.Certificates, ca1.X509Authorities(), false, "")
	testSignedByRoot(t, svid1.Certificates, ca2.X509Authorities(), false, "")
	testSignedByRoot(t, nil, ca2.X509Authorities(), false, "")
	testSignedByRoot(t, svid1.Certificates, nil, false, "")
	testSignedByRoot(t, invalidCertificate, ca1.X509Authorities(), false, "failed to verify certificate chain: x509: certificate has expired or is not yet valid")
}

func TestRawCertsToCertificates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1"))
	cert := svid.Certificates[0]

	t.Run("valid certificates", func(t *testing.T) {
		rawCerts := [][]byte{cert.Raw}
		certs, err := x509util.RawCertsToCertificates(rawCerts)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, cert.Raw, certs[0].Raw)
	})

	t.Run("invalid certificate", func(t *testing.T) {
		rawCerts := [][]byte{cert.Raw, []byte("invalid")}
		certs, err := x509util.RawCertsToCertificates(rawCerts)
		require.Error(t, err)
		assert.Nil(t, certs)
	})

	t.Run("empty input", func(t *testing.T) {
		certs, err := x509util.RawCertsToCertificates([][]byte{})
		require.NoError(t, err)
		assert.Empty(t, certs)
	})

	t.Run("nil input", func(t *testing.T) {
		certs, err := x509util.RawCertsToCertificates(nil)
		require.NoError(t, err)
		assert.Nil(t, certs)
	})
}

func TestRawCertsFromCertificates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1"))
	cert := svid.Certificates[0]

	t.Run("valid certificates", func(t *testing.T) {
		certs := []*x509.Certificate{cert}
		rawCerts := x509util.RawCertsFromCertificates(certs)
		require.Len(t, rawCerts, 1)
		assert.Equal(t, cert.Raw, rawCerts[0])
	})

	t.Run("empty input", func(t *testing.T) {
		rawCerts := x509util.RawCertsFromCertificates([]*x509.Certificate{})
		assert.Empty(t, rawCerts)
	})

	t.Run("nil input", func(t *testing.T) {
		rawCerts := x509util.RawCertsFromCertificates(nil)
		assert.Nil(t, rawCerts)
	})
}

func TestDedupeCertificates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	cert1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1")).Certificates[0]
	cert2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w2")).Certificates[0]

	t.Run("no duplicates", func(t *testing.T) {
		deduped := x509util.DedupeCertificates([]*x509.Certificate{cert1}, []*x509.Certificate{cert2})
		assert.Len(t, deduped, 2)
		assert.Equal(t, cert1.Raw, deduped[0].Raw)
		assert.Equal(t, cert2.Raw, deduped[1].Raw)
	})

	t.Run("with duplicates", func(t *testing.T) {
		deduped := x509util.DedupeCertificates([]*x509.Certificate{cert1, cert2}, []*x509.Certificate{cert2, cert1})
		assert.Len(t, deduped, 2)
		assert.Equal(t, cert1.Raw, deduped[0].Raw)
		assert.Equal(t, cert2.Raw, deduped[1].Raw)
	})

	t.Run("empty bundles", func(t *testing.T) {
		deduped := x509util.DedupeCertificates([]*x509.Certificate{}, nil)
		assert.Empty(t, deduped)
	})
}

func TestDERFromCertificates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	cert1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1")).Certificates[0]
	cert2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w2")).Certificates[0]

	t.Run("multiple certificates", func(t *testing.T) {
		der := x509util.DERFromCertificates([]*x509.Certificate{cert1, cert2})
		expected := append([]byte{}, cert1.Raw...)
		expected = append(expected, cert2.Raw...)
		assert.Equal(t, expected, der)
	})

	t.Run("nil input", func(t *testing.T) {
		der := x509util.DERFromCertificates(nil)
		assert.Nil(t, der)
	})
}

func TestCreateCertificate(t *testing.T) {
	caCert, caKey := testca.CreateCACertificate(t, nil, nil)

	template := &x509.Certificate{
		SerialNumber: caCert.SerialNumber,
	}

	cert, err := x509util.CreateCertificate(template, caCert, caCert.PublicKey, caKey)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, caCert.RawSubject, cert.RawIssuer)
}

func TestCertificateMatchesPrivateKey(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1"))
	_, otherKey := ca.CreateX509Certificate()

	matches, err := x509util.CertificateMatchesPrivateKey(svid.Certificates[0], svid.PrivateKey)
	require.NoError(t, err)
	assert.True(t, matches)

	matches, err = x509util.CertificateMatchesPrivateKey(svid.Certificates[0], otherKey)
	require.NoError(t, err)
	assert.False(t, matches)
}
