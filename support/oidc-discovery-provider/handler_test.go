package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerHTTPS(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name      string
		method    string
		path      string
		jwks      *jose.JSONWebKeySet
		modTime   time.Time
		pollTime  time.Time
		code      int
		body      string
		setKeyUse bool
	}{
		{
			name:   "GET well-known",
			method: "GET",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusOK,
			body: `{
  "issuer": "https://localhost",
  "jwks_uri": "https://localhost/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:   "PUT well-known",
			method: "PUT",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:   "GET keys with no key set",
			method: "GET",
			path:   "/keys",
			code:   http.StatusInternalServerError,
			body:   "document not available\n",
		},
		{
			name:   "GET keys with empty key set",
			method: "GET",
			path:   "/keys",
			jwks:   new(jose.JSONWebKeySet),
			code:   http.StatusNotImplemented,
			body:   "jwt not supported/enabled in this service\n",
		},
		{
			name:   "GET keys with key in set",
			method: "GET",
			path:   "/keys",
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
		{
			name:   "PUT keys",
			method: "PUT",
			path:   "/keys",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:      "GET keys with key use",
			method:    "GET",
			path:      "/keys",
			setKeyUse: true,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
		{
			name:      "GET keys with key algo",
			method:    "GET",
			path:      "/keys",
			setKeyUse: false,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:   ec256Pubkey,
						KeyID: "KEYID",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "https://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "localhost", "domain.test"), source, false, testCase.setKeyUse, nil, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}

func TestHandlerHTTPInsecure(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name     string
		method   string
		path     string
		jwks     *jose.JSONWebKeySet
		modTime  time.Time
		pollTime time.Time
		code     int
		body     string
	}{
		{
			name:   "GET well-known",
			method: "GET",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusOK,
			body: `{
  "issuer": "http://localhost",
  "jwks_uri": "http://localhost/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:   "PUT well-known",
			method: "PUT",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:   "GET keys with no key set",
			method: "GET",
			path:   "/keys",
			code:   http.StatusInternalServerError,
			body:   "document not available\n",
		},
		{
			name:   "GET keys with empty key set",
			method: "GET",
			path:   "/keys",
			jwks:   new(jose.JSONWebKeySet),
			code:   http.StatusNotImplemented,
			body:   "jwt not supported/enabled in this service\n",
		},
		{
			name:   "GET keys with key in set",
			method: "GET",
			path:   "/keys",
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
		{
			name:   "PUT keys",
			method: "PUT",
			path:   "/keys",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "localhost", "domain.test"), source, true, false, nil, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}

func TestHandlerHTTP(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name         string
		overrideHost string
		method       string
		path         string
		jwks         *jose.JSONWebKeySet
		modTime      time.Time
		pollTime     time.Time
		code         int
		body         string
	}{
		{
			name:   "GET well-known",
			method: "GET",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "https://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:         "GET well-known with punycode",
			overrideHost: "xn--n38h.test",
			method:       "GET",
			path:         "/.well-known/openid-configuration",
			code:         http.StatusOK,
			body: `{
  "issuer": "https://xn--n38h.test",
  "jwks_uri": "https://xn--n38h.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:         "GET well-known via non-default port",
			overrideHost: "domain.test:8080",
			method:       "GET",
			path:         "/.well-known/openid-configuration",
			code:         http.StatusOK,
			body: `{
  "issuer": "https://domain.test:8080",
  "jwks_uri": "https://domain.test:8080/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},

		{
			name:   "PUT well-known",
			method: "PUT",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:         "disallowed domain",
			method:       "GET",
			overrideHost: "bad.domain.test",
			path:         "/.well-known/openid-configuration",
			code:         http.StatusBadRequest,
			body:         "domain \"bad.domain.test\" is not allowed\n",
		},
		{
			name:   "GET keys with no key set",
			method: "GET",
			path:   "/keys",
			code:   http.StatusInternalServerError,
			body:   "document not available\n",
		},
		{
			name:   "GET keys with empty key set",
			method: "GET",
			path:   "/keys",
			jwks:   new(jose.JSONWebKeySet),
			code:   http.StatusNotImplemented,
			body:   "jwt not supported/enabled in this service\n",
		},
		{
			name:   "GET keys with key in set",
			method: "GET",
			path:   "/keys",
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
		{
			name:   "PUT keys",
			method: "PUT",
			path:   "/keys",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			host := "domain.test"
			if testCase.overrideHost != "" {
				host = testCase.overrideHost
			}

			r, err := http.NewRequest(testCase.method, "http://"+host+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "domain.test", "xn--n38h.test"), source, false, false, nil, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}

func TestHandlerProxied(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name     string
		method   string
		path     string
		jwks     *jose.JSONWebKeySet
		modTime  time.Time
		pollTime time.Time
		code     int
		body     string
	}{
		{
			name:   "GET well-known",
			method: "GET",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "https://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:   "PUT well-known",
			method: "PUT",
			path:   "/.well-known/openid-configuration",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:   "GET keys with no key set",
			method: "GET",
			path:   "/keys",
			code:   http.StatusInternalServerError,
			body:   "document not available\n",
		},
		{
			name:   "GET keys with empty key set",
			method: "GET",
			path:   "/keys",
			jwks:   new(jose.JSONWebKeySet),
			code:   http.StatusNotImplemented,
			body:   "jwt not supported/enabled in this service\n",
		},
		{
			name:   "GET keys with key in set",
			method: "GET",
			path:   "/keys",
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			code: http.StatusOK,
			body: `{
  "keys": [
    {
      "kty": "EC",
      "kid": "KEYID",
      "crv": "P-256",
      "alg": "ES256",
      "x": "iSt7S4ih6QLodw9wf-zdPV8bmAlDJBCRRy24_UAZY70",
      "y": "Gb4gkQCeHj7HCbZzdctcAx9dxoDgC9sudsSG7ZLIWJs"
    }
  ]
}`,
		},
		{
			name:   "PUT keys",
			method: "PUT",
			path:   "/keys",
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)
			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()
			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, nil, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)
			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}
func TestHandlerJWTIssuer(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name      string
		jwtIssuer string
		method    string
		path      string
		jwks      *jose.JSONWebKeySet
		modTime   time.Time
		pollTime  time.Time
		code      int
		body      string
	}{
		{
			name:      "GET well-known HTTPS JWT Issuer",
			jwtIssuer: "https://domain.test/some/issuer/path/issuer1",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "https://domain.test/some/issuer/path/issuer1",
  "jwks_uri": "https://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:      "GET well-known HTTP JWT Issuer",
			jwtIssuer: "http://domain.test/some/issuer/path/issuer1",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "http://domain.test/some/issuer/path/issuer1",
  "jwks_uri": "http://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:      "GET well-known JWT Issuer with trailing forward-slash",
			jwtIssuer: "http://domain.test/some/issuer/path/issuer1/",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "http://domain.test/some/issuer/path/issuer1/",
  "jwks_uri": "http://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:      "GET well-known JWT Issuer without a path with trailing forward-slash",
			jwtIssuer: "http://domain.test/",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "http://domain.test/",
  "jwks_uri": "http://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:      "GET well-known JWT Issuer without a path",
			jwtIssuer: "http://domain.test",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "http://domain.test",
  "jwks_uri": "http://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()

			u, _ := url.Parse(testCase.jwtIssuer)
			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, u, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}
func TestHandlerJWTIssuerAndJWKSURI(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name      string
		jwtIssuer string
		jwksURI   string
		method    string
		path      string
		jwks      *jose.JSONWebKeySet
		modTime   time.Time
		pollTime  time.Time
		code      int
		body      string
	}{
		{
			name:      "GET well-known HTTPS JWT Issuer and JWKS URI",
			jwtIssuer: "https://domain.test/some/issuer/path/issuer1",
			jwksURI:   "http://other.test/keys",
			method:    "GET",
			path:      "/.well-known/openid-configuration",
			code:      http.StatusOK,
			body: `{
  "issuer": "https://domain.test/some/issuer/path/issuer1",
  "jwks_uri": "http://other.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()

			u, _ := url.Parse(testCase.jwtIssuer)
			j, _ := url.Parse(testCase.jwksURI)
			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, u, j, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}
func TestHandlerAdvertisedURL(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name     string
		jwksURI  string
		method   string
		path     string
		jwks     *jose.JSONWebKeySet
		modTime  time.Time
		pollTime time.Time
		code     int
		body     string
	}{
		{
			name:    "GET well-known advertised url with path, without trailing forward-slash and https",
			jwksURI: "https://domain.test/some/issuer/path/issuer1/keys",
			method:  "GET",
			path:    "/.well-known/openid-configuration",
			code:    http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "https://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:    "GET well-known advertised url with path and without trailing forward-slash",
			jwksURI: "http://domain.test/some/issuer/path/issuer1/keys",
			method:  "GET",
			path:    "/.well-known/openid-configuration",
			code:    http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "http://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:    "GET well-known advertised url with path and trailing forward-slash",
			jwksURI: "http://domain.test/some/issuer/path/issuer1/keys",
			method:  "GET",
			path:    "/.well-known/openid-configuration",
			code:    http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "http://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:    "GET well-known advertised url with trailing forward-slash",
			jwksURI: "http://domain.test/keys",
			method:  "GET",
			path:    "/.well-known/openid-configuration",
			code:    http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "http://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:    "GET well-known advertised url without a path",
			jwksURI: "http://domain.test/keys",
			method:  "GET",
			path:    "/.well-known/openid-configuration",
			code:    http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "http://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()

			u, _ := url.Parse(testCase.jwksURI)
			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, nil, u, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}
func TestHandlerPrefix(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name             string
		serverPathPrefix string
		method           string
		path             string
		jwks             *jose.JSONWebKeySet
		modTime          time.Time
		pollTime         time.Time
		code             int
		body             string
	}{
		{
			name:             "GET well-known No Prefix",
			serverPathPrefix: "",
			method:           "GET",
			path:             "/.well-known/openid-configuration",
			code:             http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "https://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:             "GET well-known Prefix /",
			serverPathPrefix: "/",
			method:           "GET",
			path:             "/.well-known/openid-configuration",
			code:             http.StatusOK,
			body: `{
  "issuer": "https://domain.test",
  "jwks_uri": "https://domain.test/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:             "GET well-known Prefix without slash",
			serverPathPrefix: "/some/issuer/path/issuer1",
			method:           "GET",
			path:             "/some/issuer/path/issuer1/.well-known/openid-configuration",
			code:             http.StatusOK,
			body: `{
  "issuer": "https://domain.test/some/issuer/path/issuer1",
  "jwks_uri": "https://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
		{
			name:             "GET well-known Prefix with trailing forward-slash",
			serverPathPrefix: "/some/issuer/path/issuer1/",
			method:           "GET",
			path:             "/some/issuer/path/issuer1/.well-known/openid-configuration",
			code:             http.StatusOK,
			body: `{
  "issuer": "https://domain.test/some/issuer/path/issuer1/",
  "jwks_uri": "https://domain.test/some/issuer/path/issuer1/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, nil, nil, testCase.serverPathPrefix)
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}

func TestHandlerAllKeys(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	// testca issues authorities with a one hour lifetime, so a derived refresh
	// hint is a tenth of that.
	const derivedRefreshHint = 360

	fullBundle := spiffebundle.New(td)
	fullBundle.SetX509Authorities(ca.X509Authorities())
	require.NoError(t, fullBundle.AddJWTAuthority("KID", ec256Pubkey))
	fullBundle.SetRefreshHint(10 * time.Minute)
	fullBundle.SetSequenceNumber(42)

	x509OnlyBundle := spiffebundle.New(td)
	x509OnlyBundle.SetX509Authorities(ca.X509Authorities())

	jwtOnlyBundle := spiffebundle.New(td)
	require.NoError(t, jwtOnlyBundle.AddJWTAuthority("KID", ec256Pubkey))

	testCases := []struct {
		name             string
		method           string
		path             string
		serverPathPrefix string
		bundle           *spiffebundle.Bundle
		setKeyUse        bool
		code             int
		body             string
		x509Authorities  []*x509.Certificate
		jwtAuthorities   map[string]crypto.PublicKey
		refreshHint      int
		sequenceNumber   uint64
	}{
		{
			name:   "POST not allowed",
			method: "POST",
			path:   "/all-keys",
			bundle: fullBundle,
			code:   http.StatusMethodNotAllowed,
			body:   "method not allowed\n",
		},
		{
			name:   "no bundle available",
			method: "GET",
			path:   "/all-keys",
			code:   http.StatusInternalServerError,
			body:   "document not available\n",
		},
		{
			name:   "empty bundle",
			method: "GET",
			path:   "/all-keys",
			bundle: spiffebundle.New(td),
			code:   http.StatusNotImplemented,
			body:   "no keys available in this service\n",
		},
		{
			name:            "X.509 and JWT authorities",
			method:          "GET",
			path:            "/all-keys",
			bundle:          fullBundle,
			code:            http.StatusOK,
			x509Authorities: ca.X509Authorities(),
			jwtAuthorities:  map[string]crypto.PublicKey{"KID": ec256Pubkey},
			refreshHint:     600,
			sequenceNumber:  42,
		},
		{
			name:            "X.509 authorities only, refresh hint derived",
			method:          "GET",
			path:            "/all-keys",
			bundle:          x509OnlyBundle,
			code:            http.StatusOK,
			x509Authorities: ca.X509Authorities(),
			jwtAuthorities:  map[string]crypto.PublicKey{},
			refreshHint:     derivedRefreshHint,
		},
		{
			name:            "JWT authorities only, refresh hint floored",
			method:          "GET",
			path:            "/all-keys",
			bundle:          jwtOnlyBundle,
			code:            http.StatusOK,
			x509Authorities: []*x509.Certificate{},
			jwtAuthorities:  map[string]crypto.PublicKey{"KID": ec256Pubkey},
			refreshHint:     int(bundleutil.MinimumRefreshHint / time.Second),
		},
		{
			// set_key_use only applies to the keys endpoint. Overwriting the
			// use here would render the document unparseable.
			name:            "set_key_use does not affect the SPIFFE use",
			method:          "GET",
			path:            "/all-keys",
			bundle:          fullBundle,
			setKeyUse:       true,
			code:            http.StatusOK,
			x509Authorities: ca.X509Authorities(),
			jwtAuthorities:  map[string]crypto.PublicKey{"KID": ec256Pubkey},
			refreshHint:     600,
			sequenceNumber:  42,
		},
		{
			name:             "honors the server path prefix",
			method:           "GET",
			path:             "/some/issuer/path/issuer1/all-keys",
			serverPathPrefix: "/some/issuer/path/issuer1",
			bundle:           fullBundle,
			code:             http.StatusOK,
			x509Authorities:  ca.X509Authorities(),
			jwtAuthorities:   map[string]crypto.PublicKey{"KID": ec256Pubkey},
			refreshHint:      600,
			sequenceNumber:   42,
		},
		{
			name:             "not served off the prefix once one is set",
			method:           "GET",
			path:             "/all-keys",
			serverPathPrefix: "/some/issuer/path/issuer1",
			bundle:           fullBundle,
			code:             http.StatusNotFound,
			body:             "404 page not found\n",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetBundle(testCase.bundle, time.Now(), time.Now())

			r, err := http.NewRequest(testCase.method, "https://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "localhost"), source, false, testCase.setKeyUse, nil, nil, testCase.serverPathPrefix)
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			require.Equal(t, testCase.code, w.Code)
			if testCase.code != http.StatusOK {
				assert.Equal(t, testCase.body, w.Body.String())
				return
			}

			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Equal(t, "no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))

			body := w.Body.Bytes()

			// Decode the document the same way a federating SPIRE Server
			// would, to prove the two are compatible.
			actual, err := bundleutil.Decode(td, bytes.NewReader(body))
			require.NoError(t, err)
			assert.Equal(t, testCase.x509Authorities, actual.X509Authorities())
			assert.Equal(t, testCase.jwtAuthorities, actual.JWTAuthorities())

			refreshHint, ok := actual.RefreshHint()
			assert.True(t, ok)
			assert.Equal(t, time.Duration(testCase.refreshHint)*time.Second, refreshHint)

			// The sequence number is dropped by bundleutil.Decode, so read it
			// straight out of the document.
			var doc struct {
				Sequence uint64 `json:"spiffe_sequence"`
			}
			require.NoError(t, json.Unmarshal(body, &doc))
			assert.Equal(t, testCase.sequenceNumber, doc.Sequence)
		})
	}
}

func TestHandlerResponseHeaders(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       ec256Pubkey,
				KeyID:     "KEYID",
				Algorithm: "ES256",
			},
		},
	}

	testCases := []struct {
		name         string
		method       string
		path         string
		code         int
		headers      map[string]string
		absentHeader []string
	}{
		{
			name:   "GET well-known",
			method: "GET",
			path:   "/.well-known/openid-configuration",
			headers: map[string]string{
				"Content-Type":                "application/json",
				"Access-Control-Allow-Origin": "*",
			},
			// The discovery document is static, so it is left cacheable.
			absentHeader: []string{"Cache-Control", "Pragma", "Expires"},
		},
		{
			name:   "GET keys",
			method: "GET",
			path:   "/keys",
			headers: map[string]string{
				"Content-Type":                "application/json",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control":               "no-cache, no-store, must-revalidate",
				"Pragma":                      "no-cache",
				"Expires":                     "0",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(jwks, time.Time{}, time.Time{})

			r, err := http.NewRequest(testCase.method, "https://domain.test"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false, nil, nil, "")
			require.NoError(t, err)
			h.ServeHTTP(w, r)

			assert.Equal(t, http.StatusOK, w.Code)
			for name, value := range testCase.headers {
				assert.Equal(t, value, w.Header().Get(name), "header %q", name)
			}
			for _, name := range testCase.absentHeader {
				assert.Empty(t, w.Header().Values(name), "header %q should not be set", name)
			}
		})
	}
}

func domainAllowlist(t *testing.T, domains ...string) DomainPolicy {
	policy, err := DomainAllowlist(domains...)
	require.NoError(t, err)
	return policy
}
