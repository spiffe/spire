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
