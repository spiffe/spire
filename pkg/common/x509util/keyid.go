package x509util

import (
	"crypto/sha1" //nolint: gosec // usage of SHA1 is according to specification
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// GetSubjectKeyID calculates a subject key identifier by doing a SHA-1 hash
// over the ASN.1 encoding of the public key.
func GetSubjectKeyID(pubKey interface{}) ([]byte, error) {
	// Borrowed with love from cfssl under the BSD 2-Clause license
	// TODO: just use cfssl...

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
	keyID := sha1.Sum(subjectKeyInfo.SubjectPublicKey.Bytes) //nolint: gosec // usage of SHA1 is according to specification
	return keyID[:], nil
}
