package common

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
)

// keyUse is the value of the "use" parameter set on the JWKs. It matches the
// value served by the OIDC Discovery Provider when set_key_use is enabled.
const keyUse = "sig"

// ValidateJWKSOptions checks the jwt_keys_only option against the configured
// bundle format: it only applies to the jwks format.
func ValidateJWKSOptions(format bundleformat.Format, jwtKeysOnly bool) error {
	if jwtKeysOnly && format != bundleformat.JWKS {
		return fmt.Errorf("jwt_keys_only can only be used with the %q bundle format", bundleformat.JWKS)
	}
	return nil
}

// FormatBundle formats the bundle in the given format. When jwtKeysOnly is
// set, the jwks format is built by JWTKeysJWKS; otherwise the bundle is
// formatted by the plugin SDK bundleformat package.
func FormatBundle(bundle *types.Bundle, format bundleformat.Format, jwtKeysOnly bool) ([]byte, error) {
	if jwtKeysOnly && format == bundleformat.JWKS {
		return JWTKeysJWKS(bundle)
	}
	return bundleformat.NewFormatter(bundle).Format(format)
}

// JWTKeysJWKS returns a JWKS document with the JWT authorities of the bundle,
// in the form served by the OIDC Discovery Provider, so that it can be used
// to verify JWT-SVIDs by OIDC relying parties: X.509 authorities are not
// included, and every key has its "kid", its "alg" and "use" set to "sig".
func JWTKeysJWKS(bundle *types.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, errors.New("missing bundle")
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}
	for _, jwtKey := range bundle.JwtAuthorities {
		publicKey, err := x509.ParsePKIXPublicKey(jwtKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse JWT signing key %q: %w", jwtKey.KeyId, err)
		}
		alg, err := cryptoutil.JoseAlgFromPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to determine the algorithm of JWT signing key %q: %w", jwtKey.KeyId, err)
		}

		jwk := jose.JSONWebKey{
			Key:       publicKey,
			KeyID:     jwtKey.KeyId,
			Algorithm: string(alg),
			Use:       keyUse,
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}
