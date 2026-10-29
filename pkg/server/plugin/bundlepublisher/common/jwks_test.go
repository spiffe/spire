package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestJWTKeysJWKS(t *testing.T) {
	rsa2048 := testkey.MustRSA2048().Public()
	rsa4096 := testkey.MustRSA4096().Public()
	ec256 := testkey.MustEC256().Public()
	ec384 := testkey.MustEC384().Public()

	rsa1024Key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // small key on purpose, to test that it is rejected
	require.NoError(t, err)
	ec521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	ed25519Key, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	for _, tt := range []struct {
		name      string
		bundle    *types.Bundle
		setKeyUse bool
		expectAlg map[string]string
		expectErr string
	}{
		{
			name: "all supported key types",
			bundle: &types.Bundle{
				TrustDomain: "example.org",
				JwtAuthorities: []*types.JWTKey{
					jwtKey(t, "rsa2048", rsa2048),
					jwtKey(t, "rsa4096", rsa4096),
					jwtKey(t, "ec256", ec256),
					jwtKey(t, "ec384", ec384),
				},
			},
			expectAlg: map[string]string{
				"rsa2048": "RS256",
				"rsa4096": "RS256",
				"ec256":   "ES256",
				"ec384":   "ES384",
			},
		},
		{
			name:      "set key use",
			setKeyUse: true,
			bundle: &types.Bundle{
				TrustDomain: "example.org",
				JwtAuthorities: []*types.JWTKey{
					jwtKey(t, "rsa2048", rsa2048),
					jwtKey(t, "ec256", ec256),
				},
			},
			expectAlg: map[string]string{
				"rsa2048": "RS256",
				"ec256":   "ES256",
			},
		},
		{
			name: "x509 authorities are not included",
			bundle: &types.Bundle{
				TrustDomain:     "example.org",
				X509Authorities: []*types.X509Certificate{{Asn1: ca.Raw}},
				JwtAuthorities: []*types.JWTKey{
					jwtKey(t, "ec256", ec256),
				},
				RefreshHint:    60,
				SequenceNumber: 42,
			},
			expectAlg: map[string]string{
				"ec256": "ES256",
			},
		},
		{
			name: "no jwt authorities",
			bundle: &types.Bundle{
				TrustDomain:     "example.org",
				X509Authorities: []*types.X509Certificate{{Asn1: ca.Raw}},
			},
			expectAlg: map[string]string{},
		},
		{
			name: "rsa key smaller than 2048 bits",
			bundle: &types.Bundle{
				TrustDomain:    "example.org",
				JwtAuthorities: []*types.JWTKey{jwtKey(t, "rsa1024", rsa1024Key.Public())},
			},
			expectErr: `unable to determine the algorithm of JWT signing key "rsa1024": unsupported RSA key size: 128`,
		},
		{
			name: "ec p-521 key",
			bundle: &types.Bundle{
				TrustDomain:    "example.org",
				JwtAuthorities: []*types.JWTKey{jwtKey(t, "ec521", ec521Key.Public())},
			},
			expectErr: `unable to determine the algorithm of JWT signing key "ec521": unable to determine signature algorithm for EC public key size 521`,
		},
		{
			name: "ed25519 key",
			bundle: &types.Bundle{
				TrustDomain:    "example.org",
				JwtAuthorities: []*types.JWTKey{jwtKey(t, "ed25519", ed25519Key)},
			},
			expectErr: `unable to determine the algorithm of JWT signing key "ed25519": unable to determine signature algorithm for public key type ed25519.PublicKey`,
		},
		{
			name: "malformed key",
			bundle: &types.Bundle{
				TrustDomain:    "example.org",
				JwtAuthorities: []*types.JWTKey{{KeyId: "malformed", PublicKey: []byte("malformed")}},
			},
			expectErr: `unable to parse JWT signing key "malformed"`,
		},
		{
			name:      "missing bundle",
			expectErr: "missing bundle",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jwksBytes, err := JWTKeysJWKS(tt.bundle, tt.setKeyUse)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				require.Nil(t, jwksBytes)
				return
			}
			require.NoError(t, err)

			// Check the wire format: only the "keys" member, and every key
			// with exactly the members of a JWT verification key.
			var doc struct {
				Keys []map[string]any `json:"keys"`
			}
			require.NoError(t, json.Unmarshal(jwksBytes, &doc))
			require.NotNil(t, doc.Keys, "keys must be an array, even when empty")
			var raw map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(jwksBytes, &raw))
			require.Len(t, raw, 1)

			var jwks jose.JSONWebKeySet
			require.NoError(t, json.Unmarshal(jwksBytes, &jwks))
			require.Len(t, jwks.Keys, len(tt.bundle.JwtAuthorities))

			for i, jwtAuthority := range tt.bundle.JwtAuthorities {
				// Keys are kept in the order of the bundle.
				jwk := jwks.Keys[i]
				require.Equal(t, jwtAuthority.KeyId, jwk.KeyID)
				require.Equal(t, tt.expectAlg[jwk.KeyID], jwk.Algorithm)
				require.Empty(t, jwk.Certificates)

				expectedKey, err := x509.ParsePKIXPublicKey(jwtAuthority.PublicKey)
				require.NoError(t, err)
				require.Equal(t, expectedKey, jwk.Key)

				members := []string{"kty", "kid", "alg"}
				switch jwk.Key.(type) {
				case *rsa.PublicKey:
					members = append(members, "n", "e")
				case *ecdsa.PublicKey:
					members = append(members, "crv", "x", "y")
				}
				if tt.setKeyUse {
					require.Equal(t, "sig", jwk.Use)
					members = append(members, "use")
				} else {
					require.Empty(t, jwk.Use)
				}
				require.ElementsMatch(t, members, mapKeys(doc.Keys[i]))
			}
		})
	}
}

func TestValidateJWKSOptions(t *testing.T) {
	for _, tt := range []struct {
		name        string
		format      bundleformat.Format
		jwtKeysOnly bool
		setKeyUse   bool
		expectErr   string
	}{
		{name: "jwks without options", format: bundleformat.JWKS},
		{name: "spiffe without options", format: bundleformat.SPIFFE},
		{name: "pem without options", format: bundleformat.PEM},
		{name: "jwks with jwt_keys_only", format: bundleformat.JWKS, jwtKeysOnly: true},
		{name: "jwks with jwt_keys_only and set_key_use", format: bundleformat.JWKS, jwtKeysOnly: true, setKeyUse: true},
		{
			name:        "spiffe with jwt_keys_only",
			format:      bundleformat.SPIFFE,
			jwtKeysOnly: true,
			expectErr:   `jwt_keys_only can only be used with the "jwks" bundle format`,
		},
		{
			name:        "pem with jwt_keys_only",
			format:      bundleformat.PEM,
			jwtKeysOnly: true,
			expectErr:   `jwt_keys_only can only be used with the "jwks" bundle format`,
		},
		{
			name:      "jwks with set_key_use only",
			format:    bundleformat.JWKS,
			setKeyUse: true,
			expectErr: "set_key_use can only be used when jwt_keys_only is set",
		},
		{
			name:      "spiffe with set_key_use only",
			format:    bundleformat.SPIFFE,
			setKeyUse: true,
			expectErr: "set_key_use can only be used when jwt_keys_only is set",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJWKSOptions(tt.format, tt.jwtKeysOnly, tt.setKeyUse)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFormatBundle(t *testing.T) {
	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)
	bundle := &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: ca.Raw}},
		JwtAuthorities:  []*types.JWTKey{jwtKey(t, "ec256", testkey.MustEC256().Public())},
		RefreshHint:     60,
		SequenceNumber:  42,
	}

	t.Run("without jwt_keys_only the bundle is formatted by the SDK", func(t *testing.T) {
		for _, format := range []bundleformat.Format{bundleformat.JWKS, bundleformat.SPIFFE, bundleformat.PEM} {
			expected, err := bundleformat.NewFormatter(bundle).Format(format)
			require.NoError(t, err)

			actual, err := FormatBundle(bundle, format, false, false)
			require.NoError(t, err)
			require.Equal(t, expected, actual, "format %s", format)
		}
	})

	t.Run("with jwt_keys_only the jwks format is built from the JWT authorities", func(t *testing.T) {
		for _, setKeyUse := range []bool{false, true} {
			expected, err := JWTKeysJWKS(bundle, setKeyUse)
			require.NoError(t, err)

			actual, err := FormatBundle(bundle, bundleformat.JWKS, true, setKeyUse)
			require.NoError(t, err)
			require.Equal(t, expected, actual, "set_key_use %t", setKeyUse)
		}
	})
}

func jwtKey(t *testing.T, keyID string, publicKey crypto.PublicKey) *types.JWTKey {
	pkix, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	return &types.JWTKey{
		KeyId:     keyID,
		PublicKey: pkix,
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
