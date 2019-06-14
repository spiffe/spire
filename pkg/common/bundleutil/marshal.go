package bundleutil

import (
	"crypto/x509"
	"encoding/json"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type marshalConfig struct {
	refreshHint    time.Duration
	noX509SVIDKeys bool
	noJWTSVIDKeys  bool
}

type MarshalOption interface {
	configure(*marshalConfig) error
}

type marshalOption func(c *marshalConfig) error

func (o marshalOption) configure(c *marshalConfig) error {
	return o(c)
}

// OverrideRefreshHint overrides the refresh hint in the bundle
func OverrideRefreshHint(value time.Duration) MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.refreshHint = value
		return nil
	})
}

// NoX509SVIDKeys skips marshalling X509 SVID keys
func NoX509SVIDKeys() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.noX509SVIDKeys = true
		return nil
	})
}

// NoJWTSVIDKeys skips marshalling JWT SVID keys
func NoJWTSVIDKeys() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.noJWTSVIDKeys = true
		return nil
	})
}

func Marshal(bundle *Bundle, opts ...MarshalOption) ([]byte, error) {
	c := &marshalConfig{
		refreshHint: bundle.RefreshHint(),
	}
	for _, opt := range opts {
		if err := opt.configure(c); err != nil {
			return nil, err
		}
	}

	doc := bundleDoc{
		RefreshHint: int(c.refreshHint / time.Second),
	}

	if !c.noX509SVIDKeys {
		for _, rootCA := range bundle.RootCAs() {
			doc.Keys = append(doc.Keys, jose.JSONWebKey{
				Key:          rootCA.PublicKey,
				Certificates: []*x509.Certificate{rootCA},
				Use:          x509SVIDUse,
			})
		}
	}

	if !c.noJWTSVIDKeys {
		for keyID, jwtSigningKey := range bundle.JWTSigningKeys() {
			doc.Keys = append(doc.Keys, jose.JSONWebKey{
				Key:   jwtSigningKey,
				KeyID: keyID,
				Use:   jwtSVIDUse,
			})
		}
	}

	return json.MarshalIndent(doc, "", "    ")
}
