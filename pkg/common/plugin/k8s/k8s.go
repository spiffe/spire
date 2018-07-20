package k8s

import (
	"crypto/x509"
	"net/url"
	"path"
	"strings"
)

func SpiffeID(trustDomain string, cert *x509.Certificate) string {
	agentID := strings.Replace(cert.Subject.CommonName, ":", "/", -1)
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "k8s", agentID),
	}
	return u.String()
}
