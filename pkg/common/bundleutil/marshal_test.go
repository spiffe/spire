package bundleutil

import (
	"fmt"
	"testing"
	"time"

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
			out:   `{"keys":null, "spiffe_refresh_hint": 60}`,
		},
		{
			name:  "with refresh hint override",
			empty: true,
			opts: []MarshalOption{
				OverrideRefreshHint(time.Second * 10),
			},
			out: `{"keys":null, "spiffe_refresh_hint": 10}`,
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
				"spiffe_refresh_hint": 60
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
				"spiffe_refresh_hint": 60
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
				"spiffe_refresh_hint": 60
			}`, x5c(rootCA)),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			bundle := New("spiffe://domain.test")
			bundle.SetRefreshHint(time.Minute)
			if !testCase.empty {
				bundle.AppendRootCA(rootCA)
				require.NoError(t, bundle.AppendJWTSigningKey("FOO", testKey.Public()))
			}
			bundleBytes, err := Marshal(bundle, testCase.opts...)
			require.NoError(t, err)
			require.JSONEq(t, testCase.out, string(bundleBytes))
		})
	}
}
