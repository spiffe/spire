package api

import (
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type X509SVID struct {
	ID        spiffeid.ID
	CertChain []*x509.Certificate
	ExpiresAt time.Time
}
