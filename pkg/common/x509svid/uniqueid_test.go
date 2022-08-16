package x509svid

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestUniqueIDAttribute(t *testing.T) {
	name := pkix.Name{
		Names: []pkix.AttributeTypeAndValue{
			UniqueIDAttribute(spiffeid.RequireFromString("spiffe://example.org/foo")),
		},
	}
	require.Equal(t,
		"2.5.4.45=#13206333343036663962313263656234663963393438333138633537396239303562",
		name.String())
}
