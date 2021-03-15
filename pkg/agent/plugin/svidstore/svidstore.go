package svidstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type SVIDStore interface {
	catalog.PluginInfo

	DeleteX509SVID(ctx context.Context, secretsData []string) error
	PutX509SVID(context.Context, *X509SVID) error
}

type X509SVID struct {
	// X509-SVID to be stored
	SVID *SVID

	// Data relevant for plugin to identify secret
	SecretsData []string
	// Federated bundles to store
	FederatedBundles map[string][]*x509.Certificate
}

type SVID struct {
	// SPIFFE ID of the SVID.
	SpiffeID spiffeid.ID

	// Certificate and intermediates
	CertChain []*x509.Certificate

	// Private key
	PrivateKey crypto.PrivateKey

	// Bundle certificates
	Bundle []*x509.Certificate

	// Expiration timestamp
	ExpiresAt time.Time
}
