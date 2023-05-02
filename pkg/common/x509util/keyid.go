package x509util

import (
	"crypto/sha1" //nolint: gosec // usage of SHA1 is according to specification
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
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

// SubjectKeyIDToString parse Subject Key ID into string
func SubjectKeyIDToString(ski []byte) string {
	if len(ski) == 0 {
		return ""
	}

	// Create an hex with colons every 2 characters,
	// this is the output generated by openssl
	encodedByte := make([]byte, hex.EncodedLen(len(ski)))
	hex.Encode(encodedByte, ski)

	var finalHex []byte
	for i := 0; i < len(encodedByte); i += 2 {
		finalHex = append(finalHex, encodedByte[i], encodedByte[i+1], ':')
	}
	return string(finalHex[:len(finalHex)-1])
}
