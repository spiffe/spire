package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
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
  "subject_types_supported": [],
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
			code:   http.StatusOK,
			body: `{
  "keys": null
}`,
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
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "https://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h := NewHandler(log, domainAllowlist(t, "localhost", "domain.test"), source, false, testCase.setKeyUse)
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
  "subject_types_supported": [],
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
			code:   http.StatusOK,
			body: `{
  "keys": null
}`,
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
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h := NewHandler(log, domainAllowlist(t, "localhost", "domain.test"), source, true, false)
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
  "subject_types_supported": [],
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
  "subject_types_supported": [],
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
  "subject_types_supported": [],
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
			code:   http.StatusOK,
			body: `{
  "keys": null
}`,
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
		testCase := testCase
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

			h := NewHandler(log, domainAllowlist(t, "domain.test", "xn--n38h.test"), source, false, false)
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
  "subject_types_supported": [],
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
			code:   http.StatusOK,
			body: `{
  "keys": null
}`,
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
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime, testCase.pollTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			r.Header.Add("X-Forwarded-Scheme", "https")
			r.Header.Add("X-Forwarded-Host", "domain.test")
			w := httptest.NewRecorder()

			h := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, false)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}
}

func domainAllowlist(t *testing.T, domains ...string) DomainPolicy {
	policy, err := DomainAllowlist(domains...)
	require.NoError(t, err)
	return policy
}
