package bundleutil

import (
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	rootCA := createCACertificate(t)
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")
	emptyBundle := spiffebundle.New(trustDomain)
	emptyBundle.SetRefreshHint(0)
	testCases := []struct {
		name   string
		doc    string
		err    string
		bundle *spiffebundle.Bundle
	}{
		{
			name:   "empty bundle",
			doc:    "{}",
			bundle: emptyBundle,
		},
		{
			name: "entry missing use",
			doc: `{
				"keys": [
					{
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			err: "missing use for key entry 0",
		},
		{
			name: "unrecognized use",
			doc: `{
				"keys": [
					{
						"use": "bad stuff",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			err: `unrecognized use "bad stuff" for key entry 0`,
		},
		{
			name: "x509-svid without x5c",
			doc: `{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			err: "expected a single certificate in x509-svid entry 0; got 0",
		},
		{
			name: "x509-svid with more than one x5c",
			doc: fmt.Sprintf(`{
				"keys": [
					{
						"use": "x509-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [
							%q,
							%q
						]
					}
				]
			}`, x5c(rootCA), x5c(rootCA)),
			err: "expected a single certificate in x509-svid entry 0; got 2",
		},
		{
			name: "jwt-svid with no keyid",
			doc: `{
				"keys": [
					{
						"use": "jwt-svid",
						"kty": "EC",
						"crv": "P-256",
						"x": "kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y": "qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA"
					}
				]
			}`,
			err: "missing key ID in jwt-svid entry 0",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle, err := Unmarshal(trustDomain, []byte(testCase.doc))
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.bundle, bundle)
		})
	}
}
