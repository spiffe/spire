package tpmdevid

import (
	"crypto/sha1" //nolint: gosec // SHA1 use is according to specification
	"crypto/x509"
	"encoding/hex"
)

func buildSelectorValues(leaf *x509.Certificate, chains [][]*x509.Certificate) []string {
	selectorValues := []string{}

	if leaf.Subject.CommonName != "" {
		selectorValues = append(selectorValues, "subject:cn:"+leaf.Subject.CommonName)
	}

	if leaf.Issuer.CommonName != "" {
		selectorValues = append(selectorValues, "issuer:cn:"+leaf.Issuer.CommonName)
	}

	// Used to avoid duplicating selectors.
	fingerprints := map[string]*x509.Certificate{}
	for _, chain := range chains {
		// Iterate over all the certs in the chain (skip leaf at the 0 index)
		for _, cert := range chain[1:] {
			fp := Fingerprint(cert)
			// If the same fingerprint is generated, continue with the next certificate, because
			// a selector should have been already created for it.
			if _, ok := fingerprints[fp]; ok {
				continue
			}
			fingerprints[fp] = cert

			selectorValues = append(selectorValues, "ca:fingerprint:"+fp)
		}
	}

	return selectorValues
}

func Fingerprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw) //nolint: gosec // SHA1 use is according to specification
	return hex.EncodeToString(sum[:])
}
