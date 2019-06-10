package bundle

import (
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/bundleutil"
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
			out:   `{"keys":null}`,
		},
		{
			name:  "with refresh hint",
			empty: true,
			opts: []MarshalOption{
				WithRefreshHint(time.Second * 10),
			},
			out: `{"keys":null, "spiffe_refresh_hint": 10}`,
		},
		{
			name:  "with sequence",
			empty: true,
			opts: []MarshalOption{
				WithSequence(39),
			},
			out: `{"keys":null, "spiffe_sequence": 39}`,
		},
		{
			name: "with root CA and JWT signing key",
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
				]
			}`, x5c(rootCA)),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle := bundleutil.New("spiffe://domain.test")
			if !testCase.empty {
				bundle.AppendRootCA(rootCA)
				bundle.AppendJWTSigningKey("FOO", testKey.Public())
			}
			bundleBytes, err := Marshal(bundle, testCase.opts...)
			require.NoError(t, err)
			require.JSONEq(t, testCase.out, string(bundleBytes))
		})
	}
}
