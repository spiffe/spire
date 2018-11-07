package bundleutil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBundleFromJWKSMissingTrustDomainID(t *testing.T) {
	bundle, err := BundleFromJWKSBytes([]byte(`{
	"keys": [
		{
			"use": "spiffe-x509",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	]
}`))
	require.EqualError(t, err, "JWKS missing trust domain id")
	require.Nil(t, bundle)
}

func TestBundleFromJWKSInvalidTrustDomainID(t *testing.T) {
	bundle, err := BundleFromJWKSBytes([]byte(`{
	"keys": [
		{
			"use": "spiffe-x509",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	],
	"spiffe-td": "whatever"
}`))
	require.EqualError(t, err, "JWKS trust domain id is invalid: \"whatever\" is not a valid trust domain SPIFFE ID: invalid scheme")
	require.Nil(t, bundle)
}

func TestBundleFromJWKSX509EntryMissingCert(t *testing.T) {
	bundle, err := BundleFromJWKSBytes([]byte(`{
	"keys": [
		{
			"use": "spiffe-x509",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	],
	"spiffe-td": "spiffe://otherdomain.test"
}`))
	require.EqualError(t, err, "expected 1 certificate in X509 key entry 0; got 0")
	require.Nil(t, bundle)
}

func TestBundleFromJWKSJWTEntryMissingKeyID(t *testing.T) {
	bundle, err := BundleFromJWKSBytes([]byte(`{
	"keys": [
		{
			"use": "spiffe-jwt",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	],
	"spiffe-td": "spiffe://otherdomain.test"
}`))
	require.EqualError(t, err, "expected key ID in JWT key entry 0")
	require.Nil(t, bundle)
}

func TestBundleFromJWKSUnexpectedUse(t *testing.T) {
	bundle, err := BundleFromJWKSBytes([]byte(`{
	"keys": [
		{
			"use": "FOO",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	],
	"spiffe-td": "spiffe://otherdomain.test"
}`))
	require.EqualError(t, err, "unexpected use \"FOO\" for key entry 0")
	require.Nil(t, bundle)
}

func TestBundleFromJWKSSuccess(t *testing.T) {
	jwksIn := `{
	"keys": [
		{
			"use": "spiffe-x509",
			"kty": "EC",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
			"x5c": [
				"MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
			]
		},
		{
			"use": "spiffe-jwt",
			"kty": "EC",
			"kid": "KID",
			"crv": "P-256",
			"x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
			"y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
		}
	],
	"spiffe-td": "spiffe://otherdomain.test"
}`
	bundle, err := BundleFromJWKSBytes([]byte(jwksIn))
	require.NoError(t, err)
	require.NotNil(t, bundle)

	rootCAs := bundle.RootCAs()
	require.Len(t, rootCAs, 1)

	jwtSigningKeys := bundle.JWTSigningKeys()
	require.Len(t, jwtSigningKeys, 1)
	jwtSigningKey := jwtSigningKeys["KID"]
	require.NotNil(t, jwtSigningKey)

	jwksOut, err := json.Marshal(JWKSFromBundle(bundle))
	require.NoError(t, err)
	require.JSONEq(t, jwksIn, string(jwksOut))
}
