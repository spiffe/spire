package bundleutil

import (
	"crypto/mldsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	rootCA := createCACertificate(t)

	testCases := []struct {
		name       string
		empty      bool
		withWITKey bool
		opts       []MarshalOption
		out        string
	}{
		{
			name:  "empty bundle",
			empty: true,
			out:   `{"keys":[], "spiffe_refresh_hint": 60, "spiffe_sequence": 42}`,
		},
		{
			name:  "with refresh hint override",
			empty: true,
			opts: []MarshalOption{
				OverrideRefreshHint(time.Second * 10),
			},
			out: `{"keys":[], "spiffe_refresh_hint": 10, "spiffe_sequence": 42}`,
		},
		{
			name:  "with sequence number override",
			empty: true,
			opts: []MarshalOption{
				OverrideSequenceNumber(1),
			},
			out: `{"keys":[], "spiffe_refresh_hint": 60, "spiffe_sequence": 1}`,
		},
		{
			name: "without X509 SVID keys",
			opts: []MarshalOption{
				NoX509SVIDKeys(),
			},
			out: `{
				"keys": [
					{
						"use": "jwt-svid",
						"kid": "FOO",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				],
				"spiffe_refresh_hint": 60,
				"spiffe_sequence": 42
			}`,
		},

		{
			name: "without JWT SVID keys",
			opts: []MarshalOption{
				NoJWTSVIDKeys(),
			},
			out: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							"%s"
						]
					}
				],
				"spiffe_refresh_hint": 60,
				"spiffe_sequence": 42
			}`, x5c(rootCA)),
		},
		{
			name: "with X509 and JWT SVID keys",
			out: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							"%s"
						]
					},
					{
						"use": "jwt-svid",
						"kid": "FOO",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				],
				"spiffe_refresh_hint": 60,
				"spiffe_sequence": 42
			}`, x5c(rootCA)),
		},
		{
			name: "as standard JWKS",
			opts: []MarshalOption{
				StandardJWKS(),
			},
			out: fmt.Sprintf(`{
				"keys": [
					{
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							"%s"
						]
					},
					{
						"kid": "FOO",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`, x5c(rootCA)),
		},
		{
			name:       "without WIT SVID keys",
			withWITKey: true,
			opts: []MarshalOption{
				NoWITSVIDKeys(),
			},
			out: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							"%s"
						]
					},
					{
						"use": "jwt-svid",
						"kid": "FOO",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				],
				"spiffe_refresh_hint": 60,
				"spiffe_sequence": 42
			}`, x5c(rootCA)),
		},
		{
			name:       "with all SVID keys",
			withWITKey: true,
			out: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							"%s"
						]
					},
					{
						"use": "jwt-svid",
						"kid": "FOO",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					},
					{
						"use": "wit-svid",
						"kid": "BAR",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				],
				"spiffe_refresh_hint": 60,
				"spiffe_sequence": 42
			}`, x5c(rootCA)),
		},
	}

	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle := spiffebundle.New(trustDomain)
			bundle.SetRefreshHint(time.Minute)
			bundle.SetSequenceNumber(42)
			if !testCase.empty {
				bundle.AddX509Authority(rootCA)
				require.NoError(t, bundle.AddJWTAuthority("FOO", testKey.Public()))
			}
			if testCase.withWITKey {
				require.NoError(t, bundle.AddWITAuthority("BAR", testKey.Public()))
			}
			bundleBytes, err := Marshal(bundle, testCase.opts...)
			require.NoError(t, err)
			require.JSONEq(t, testCase.out, string(bundleBytes))
		})
	}
}

func TestMarshalX509SVIDBundle(t *testing.T) {
	rootCA := createCACertificate(t)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Minute)
	bundle.SetSequenceNumber(42)
	bundle.AddX509Authority(rootCA)
	require.NoError(t, bundle.AddJWTAuthority("FOO", testKey.Public()))
	require.NoError(t, bundle.AddWITAuthority("BAR", testKey.Public()))

	bundleBytes, err := MarshalX509SVIDBundle(bundle)
	require.NoError(t, err)
	require.JSONEq(t, fmt.Sprintf(`{
		"keys": [
			{
				"use": "x509-svid",
				"kty": "EC",
				"crv": "P-256",
				"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
				"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
				"x5c": ["%s"]
			}
		],
		"spiffe_refresh_hint": 60,
		"spiffe_sequence": 42
	}`, x5c(rootCA)), string(bundleBytes))
}

func TestMarshalJWTSVIDBundle(t *testing.T) {
	rootCA := createCACertificate(t)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Minute)
	bundle.SetSequenceNumber(42)
	bundle.AddX509Authority(rootCA)
	require.NoError(t, bundle.AddJWTAuthority("FOO", testKey.Public()))
	require.NoError(t, bundle.AddWITAuthority("BAR", testKey.Public()))

	bundleBytes, err := MarshalJWTSVIDBundle(bundle)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"keys": [
			{
				"use": "jwt-svid",
				"kid": "FOO",
				"kty": "EC",
				"crv": "P-256",
				"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
				"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
			}
		],
		"spiffe_refresh_hint": 60,
		"spiffe_sequence": 42
	}`, string(bundleBytes))
}

func TestMarshalWITSVIDBundle(t *testing.T) {
	rootCA := createCACertificate(t)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")

	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Minute)
	bundle.SetSequenceNumber(42)
	bundle.AddX509Authority(rootCA)
	require.NoError(t, bundle.AddJWTAuthority("FOO", testKey.Public()))
	require.NoError(t, bundle.AddWITAuthority("BAR", testKey.Public()))

	bundleBytes, err := MarshalWITSVIDBundle(bundle)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"keys": [
			{
				"use": "wit-svid",
				"kid": "BAR",
				"kty": "EC",
				"crv": "P-256",
				"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
				"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
			}
		],
		"spiffe_refresh_hint": 60,
		"spiffe_sequence": 42
	}`, bundleBytes)
}

func TestMarshalMLDSAKeys(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")
	jwtKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	witKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)

	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Minute)
	bundle.SetSequenceNumber(42)
	require.NoError(t, bundle.AddJWTAuthority("FOO", jwtKey.Public()))
	require.NoError(t, bundle.AddWITAuthority("BAR", witKey.Public()))

	// Stored form
	protoBundle, err := SPIFFEBundleToProto(bundle)
	require.NoError(t, err)
	fromProto, err := SPIFFEBundleFromProto(protoBundle)
	require.NoError(t, err)
	require.True(t, bundle.Equal(fromProto))

	// Published form
	bundleBytes, err := Marshal(bundle)
	require.NoError(t, err)
	var jwks struct {
		Keys []struct {
			Use string `json:"use"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(bundleBytes, &jwks))
	require.Len(t, jwks.Keys, 2)
	require.Equal(t, "jwt-svid", jwks.Keys[0].Use)
	require.Equal(t, "AKP", jwks.Keys[0].Kty)
	require.Equal(t, "ML-DSA-65", jwks.Keys[0].Alg)
	require.Equal(t, "wit-svid", jwks.Keys[1].Use)
	require.Equal(t, "AKP", jwks.Keys[1].Kty)
	require.Equal(t, "ML-DSA-87", jwks.Keys[1].Alg)

	parsed, err := spiffebundle.Parse(trustDomain, bundleBytes)
	require.NoError(t, err)
	require.True(t, bundle.Equal(parsed))
}
