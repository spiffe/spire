package bundleutil

import (
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
		name  string
		empty bool
		opts  []MarshalOption
		out   string
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
			bundleBytes, err := Marshal(bundle, testCase.opts...)
			require.NoError(t, err)
			require.JSONEq(t, testCase.out, string(bundleBytes))
		})
	}
}
