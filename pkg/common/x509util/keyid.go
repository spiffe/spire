package x509util

import (
	"crypto/sha1" //nolint: gosec // usage of SHA1 is according to RFC 5280
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/spiffe/spire/pkg/common/util"
)

var x509utilsha256skid = util.FIPS140Only()

// GetSubjectKeyID calculates a subject key identifier by doing a hash
// over the ASN.1 encoding of the public key.
func GetSubjectKeyID(pubKey any) ([]byte, error) {
	// Borrowed with love from cfssl under the BSD 2-Clause license.
	encodedPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	var subjectKeyInfo = struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{}
	if _, err := asn1.Unmarshal(encodedPubKey, &subjectKeyInfo); err != nil {
		return nil, err
	}

	// Borrowed with love from Go std lib crypto/x509 under the BSD 3-Clause license.
	if x509utilsha256skid {
		// SubjectKeyId generated using method 1 in RFC 7093, Section 2:
		//    1) The keyIdentifier is composed of the leftmost 160-bits of the
		//    SHA-256 hash of the value of the BIT STRING subjectPublicKey
		//    (excluding the tag, length, and number of unused bits).
		h := sha256.Sum256(subjectKeyInfo.SubjectPublicKey.Bytes)
		return h[:20], nil
	} else {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(subjectKeyInfo.SubjectPublicKey.Bytes) //nolint: gosec // usage of SHA1 is according to RFC 5280
		return h[:], nil
	}
}

// SubjectKeyIDToString parse Subject Key ID into string
func SubjectKeyIDToString(ski []byte) string {
	serialHex := fmt.Sprintf("%x", ski)
	if len(serialHex)%2 == 1 {
		// Append leading 0 in cases where hexadecimal representation is odd number of characters
		// in order to be more consistent with other tooling that displays certificate serial numbers.
		serialHex = "0" + serialHex
	}

	return serialHex
}
