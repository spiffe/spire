package federation

import (
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"gopkg.in/square/go-jose.v2"
)

type bundleDoc struct {
	jose.JSONWebKeySet
	Sequence    uint64 `json:"spiffe_sequence,omitempty"`
	RefreshHint int64  `json:"spiffe_refresh_hint,omitempty"`
}

type marshalConfig struct {
	refreshHint int64
	sequence    uint64
}

type MarshalOption interface {
	configure(*marshalConfig) error
}

type marshalOption func(c *marshalConfig) error

func (o marshalOption) configure(c *marshalConfig) error {
	return o(c)
}

func WithRefreshHint(value time.Duration) MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.refreshHint = int64(value / time.Second)
		return nil
	})
}

func WithSequence(value uint64) MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.sequence = value
		return nil
	})
}

func MarshalBundle(bundle *bundleutil.Bundle, opts ...MarshalOption) ([]byte, error) {
	c := new(marshalConfig)
	for _, opt := range opts {
		if err := opt.configure(c); err != nil {
			return nil, err
		}
	}

	doc := bundleDoc{
		Sequence:    c.sequence,
		RefreshHint: c.refreshHint,
	}

	for _, rootCA := range bundle.RootCAs() {
		doc.Keys = append(doc.Keys, jose.JSONWebKey{
			Key:          rootCA.PublicKey,
			Certificates: []*x509.Certificate{rootCA},
			Use:          "x509-svid",
		})
	}
	for keyID, jwtSigningKey := range bundle.JWTSigningKeys() {
		doc.Keys = append(doc.Keys, jose.JSONWebKey{
			Key:   jwtSigningKey,
			KeyID: keyID,
			Use:   "jwt-svid",
		})
	}

	return json.MarshalIndent(doc, "", "\t")
}
