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
	keyBytes, err := subjectPublicKeyBytes(pubKey)
	if err != nil {
		return nil, err
	}
	if x509utilsha256skid {
		return sha256SubjectKeyID(keyBytes), nil
	}
	return sha1SubjectKeyID(keyBytes), nil
}

// GetSHA256SubjectKeyID calculates a subject key identifier by doing a SHA-256
// hash over the ASN.1 encoding of the public key, no matter if FIPS 140 mode is
// enabled or not.
func GetSHA256SubjectKeyID(pubKey any) ([]byte, error) {
	keyBytes, err := subjectPublicKeyBytes(pubKey)
	if err != nil {
		return nil, err
	}
	return sha256SubjectKeyID(keyBytes), nil
}

// GetSubjectKeyIDs calculates every subject key identifier that a certificate
// issuer may have derived from the public key, SHA-256 first. Use it to look
// up an identifier that was taken from a certificate or stored by an older
// version, since RFC 5280 leaves the derivation to the issuer and Go switched
// from SHA-1 to SHA-256 when it fills in a missing subject key identifier. In
// FIPS 140-only mode SHA-1 cannot be used, so only the SHA-256 identifier is
// returned.
func GetSubjectKeyIDs(pubKey any) ([][]byte, error) {
	keyBytes, err := subjectPublicKeyBytes(pubKey)
	if err != nil {
		return nil, err
	}
	if x509utilsha256skid {
		return [][]byte{sha256SubjectKeyID(keyBytes)}, nil
	}
	return [][]byte{sha256SubjectKeyID(keyBytes), sha1SubjectKeyID(keyBytes)}, nil
}

// subjectPublicKeyBytes returns the value of the BIT STRING subjectPublicKey
// (excluding the tag, length, and number of unused bits).
func subjectPublicKeyBytes(pubKey any) ([]byte, error) {
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
	return subjectKeyInfo.SubjectPublicKey.Bytes, nil
}

// sha256SubjectKeyID generates a SubjectKeyId using method 1 in RFC 7093,
// Section 2: the leftmost 160 bits of the SHA-256 hash of the value of the
// BIT STRING subjectPublicKey (excluding the tag, length, and number of
// unused bits). Borrowed with love from Go std lib crypto/x509 under the
// BSD 3-Clause license.
func sha256SubjectKeyID(keyBytes []byte) []byte {
	h := sha256.Sum256(keyBytes)
	return h[:20]
}

// sha1SubjectKeyID generates a SubjectKeyId using method 1 in RFC 5280,
// Section 4.2.1.2: the 160-bit SHA-1 hash of the value of the BIT STRING
// subjectPublicKey (excluding the tag, length, and number of unused bits).
func sha1SubjectKeyID(keyBytes []byte) []byte {
	h := sha1.Sum(keyBytes) //nolint: gosec // usage of SHA1 is according to RFC 5280
	return h[:]
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
