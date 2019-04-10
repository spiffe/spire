package bundleutil

import (
	"crypto/x509"
	"encoding/json"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	jwtUse  = "spiffe-jwt"
	x509Use = "spiffe-x509"
)

func JWTJWKSBytesFromBundle(bundle *Bundle) ([]byte, error) {
	jwksBytes, err := json.Marshal(JWTJWKSFromBundle(bundle))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return jwksBytes, nil
}

func JWTJWKSFromBundle(bundle *Bundle) *jose.JSONWebKeySet {
	jwks := new(jose.JSONWebKeySet)
	for keyID, jwtSigningKey := range bundle.JWTSigningKeys() {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtSigningKey,
			KeyID: keyID,
			// TODO: fill in with proper use value when it is known
			Use: jwtUse,
		})
	}
	return jwks
}

type JWKS struct {
	jose.JSONWebKeySet

	TrustDomainID string `json:"spiffe-td"`
}

func JWKSFromBundleProto(bundleProto *common.Bundle) (*JWKS, error) {
	bundle, err := BundleFromProto(bundleProto)
	if err != nil {
		return nil, err
	}
	return JWKSFromBundle(bundle), nil
}

func JWKSFromBundle(bundle *Bundle) *JWKS {
	jwks := &JWKS{
		TrustDomainID: bundle.TrustDomainID(),
	}
	for _, rootCA := range bundle.RootCAs() {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:          rootCA.PublicKey,
			Certificates: []*x509.Certificate{rootCA},
			// TODO: fill in with proper use value when it is known
			Use: x509Use,
		})
	}
	for keyID, jwtSigningKey := range bundle.JWTSigningKeys() {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtSigningKey,
			KeyID: keyID,
			// TODO: fill in with proper use value when it is known
			Use: jwtUse,
		})
	}
	return jwks
}

func BundleFromJWKSBytes(jwksBytes []byte) (*Bundle, error) {
	jwks := new(JWKS)
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return nil, errs.Wrap(err)
	}
	return BundleFromJWKS(jwks)
}

func BundleFromJWKS(jwks *JWKS) (*Bundle, error) {
	if jwks.TrustDomainID == "" {
		return nil, errs.New("JWKS missing trust domain id")
	}
	trustDomainID, err := idutil.NormalizeSpiffeID(jwks.TrustDomainID, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, errs.New("JWKS trust domain id is invalid: %v", err)
	}
	bundle := New(trustDomainID)
	for i, key := range jwks.Keys {
		switch key.Use {
		case x509Use:
			if len(key.Certificates) != 1 {
				return nil, errs.New("expected 1 certificate in X509 key entry %d; got %d", i, len(key.Certificates))
			}
			bundle.AppendRootCA(key.Certificates[0])
		case jwtUse:
			if key.KeyID == "" {
				return nil, errs.New("expected key ID in JWT key entry %d", i)
			}
			if err := bundle.AppendJWTSigningKey(key.KeyID, key.Key); err != nil {
				return nil, errs.New("failed to add JWT key entry %d: %v", i, err)
			}
		default:
			return nil, errs.New("unexpected use %q for key entry %d", key.Use, i)
		}
	}

	return bundle, nil
}
