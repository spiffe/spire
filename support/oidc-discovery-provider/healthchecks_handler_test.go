package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCheckHandler(t *testing.T) {
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
	}{
		{
			name:   "Check Live State with no Keyset and valid threshold",
			method: "GET",
			path:   "/live",
			code:   http.StatusOK,
		},
		{
			name:   "Check Live State with Keyset and valid threshold",
			method: "GET",
			path:   "/live",
			code:   http.StatusOK,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			pollTime: time.Now(),
		},
		{
			name:   "Check Live State with Keyset and invalid threshold",
			method: "GET",
			path:   "/live",
			code:   http.StatusInternalServerError,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			pollTime: time.Now().Add(-time.Minute * 5),
		},
		{
			name:   "Check Ready State with Keyset and valid threshold",
			method: "GET",
			path:   "/ready",
			code:   http.StatusOK,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			pollTime: time.Now(),
		},
		{
			name:   "Check Ready State with Keyset and invalid threshold",
			method: "GET",
			path:   "/ready",
			code:   http.StatusInternalServerError,
			jwks: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       ec256Pubkey,
						KeyID:     "KEYID",
						Algorithm: "ES256",
					},
				},
			},
			pollTime: time.Now().Add(-time.Minute * 5),
		},
		{
			name:   "Check Ready State without Keyset",
			method: "GET",
			path:   "/ready",
			code:   http.StatusInternalServerError,
			jwks:   nil,
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
			c := Config{}
			c.ServerAPI = &ServerAPIConfig{}
			c.HealthChecks = &HealthChecksConfig{BindPort: 8008, ReadyPath: "/ready", LivePath: "/live"}
			h := NewHealthChecksHandler(source, &c)
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
		})
	}
}
