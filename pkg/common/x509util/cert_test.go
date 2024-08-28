package x509util_test

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
)

func TestIsSignedByRoot(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca1 := testca.New(t, td)
	intermediate := ca1.ChildCA(testca.WithID(td.ID()))
	svid1 := intermediate.CreateX509SVID(spiffeid.RequireFromPath(td, "/w1"))

	ca2 := testca.New(t, td)
	svid2 := ca2.CreateX509SVID(spiffeid.RequireFromPath(td, "/w2"))

	testSignedByRoot := func(t *testing.T, chain []*x509.Certificate, rootCAs []*x509.Certificate, expect bool) {
		isSigned := x509util.IsSignedByRoot(chain, rootCAs)
		if expect {
			assert.True(t, isSigned, "Expected chain to be signed by root")
		} else {
			assert.False(t, isSigned, "Expected chain NOT to be signed by root")
		}
	}

	testSignedByRoot(t, svid1.Certificates, ca1.X509Authorities(), true)
	testSignedByRoot(t, svid2.Certificates, ca2.X509Authorities(), true)
	testSignedByRoot(t, svid2.Certificates, ca1.X509Authorities(), false)
	testSignedByRoot(t, svid1.Certificates, ca2.X509Authorities(), false)
	testSignedByRoot(t, nil, ca2.X509Authorities(), false)
	testSignedByRoot(t, svid1.Certificates, nil, false)
}
