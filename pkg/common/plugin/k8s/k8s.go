package k8s

import (
	"crypto/x509"
	"net/url"
	"path"
)

func SpiffeID(trustDomain string, cert *x509.Certificate) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "k8s", cert.Subject.CommonName),
	}
	return u.String()
}
