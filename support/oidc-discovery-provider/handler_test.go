package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestHandler(t *testing.T) {
	testCases := []struct {
		name    string
		method  string
		path    string
		jwks    *jose.JSONWebKeySet
		modTime time.Time
		code    int
		body    string
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
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()

			h := NewHandler("domain.test", source)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
			assert.Equal(t, testCase.body, w.Body.String())
		})
	}

}

type FakeKeySetSource struct {
	mu      sync.Mutex
	jwks    *jose.JSONWebKeySet
	modTime time.Time
}

func (s *FakeKeySetSource) SetKeySet(jwks *jose.JSONWebKeySet, modTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwks = jwks
	s.modTime = modTime
}

func (s *FakeKeySetSource) FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwks == nil {
		return nil, time.Time{}, false
	}
	return s.jwks, s.modTime, true
}

func (s *FakeKeySetSource) Close() error {
	return nil
}
