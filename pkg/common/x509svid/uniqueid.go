package x509svid

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	uniqueIDOID = asn1.ObjectIdentifier{2, 5, 4, 45}
)

// UniqueIDAttribute returns a X.500 Unique ID attribute (OID 2.5.4.45) for the
// given SPIFFE ID for inclusion in an X509-SVID to satisfy RFC 5280
// requirements that the subject "DN MUST be unique for each subject entity
// certified by the one CA as defined by the issuer field" (see issue #3110 for
// the discussion on this).
//
// The unique ID is composed of a SHA256 hash of the SPIFFE ID, truncated to
// 128-bits (16 bytes), and then hex encoded. This *SHOULD* be large enough to
// provide collision resistance on the input domain (i.e. registration entry
// SPIFFE IDs registered with this server), which ranges from very- to
// somewhat-restricted depending on the registration scheme and how much
// influence an attacker can have on workload registration.
func UniqueIDAttribute(id spiffeid.ID) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  uniqueIDOID,
		Value: calculateUniqueIDValue(id),
	}
}

func calculateUniqueIDValue(id spiffeid.ID) string {
	h := sha256.New()
	_, _ = io.WriteString(h, id.String())
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:len(sum)/2])
}
