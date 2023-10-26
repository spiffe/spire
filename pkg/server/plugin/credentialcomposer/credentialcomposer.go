package credentialcomposer

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type CredentialComposer interface {
	catalog.PluginInfo

	ComposeServerX509CA(ctx context.Context, attributes X509CAAttributes) (X509CAAttributes, error)
	ComposeServerX509SVID(ctx context.Context, attributes X509SVIDAttributes) (X509SVIDAttributes, error)
	ComposeAgentX509SVID(ctx context.Context, id spiffeid.ID, publicKey crypto.PublicKey, attributes X509SVIDAttributes) (X509SVIDAttributes, error)
	ComposeWorkloadX509SVID(ctx context.Context, id spiffeid.ID, publicKey crypto.PublicKey, attributes X509SVIDAttributes) (X509SVIDAttributes, error)
	ComposeWorkloadJWTSVID(ctx context.Context, id spiffeid.ID, attributes JWTSVIDAttributes) (JWTSVIDAttributes, error)
}

type X509CAAttributes struct {
	Subject           pkix.Name
	PolicyIdentifiers []asn1.ObjectIdentifier
	ExtraExtensions   []pkix.Extension
}

type X509SVIDAttributes struct {
	Subject         pkix.Name
	DNSNames        []string
	ExtraExtensions []pkix.Extension
}

type JWTSVIDAttributes struct {
	Claims map[string]any
}
