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

func TestHealthCheckHandler(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	testCases := []struct {
		name    string
		method  string
		path    string
		jwks    *jose.JSONWebKeySet
		modTime time.Time
		code    int
	}{
		{
			name:   "Check Ready State",
			method: "GET",
			path:   "/ready",
			code:   http.StatusOK,
		},
		{
			name:   "Check Live State with Keyset",
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
		},
		{
			name:   "Check Live State without Keyset",
			method: "GET",
			path:   "/live",
			code:   http.StatusInternalServerError,
			jwks:   nil,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			source := new(FakeKeySetSource)
			source.SetKeySet(testCase.jwks, testCase.modTime)

			r, err := http.NewRequest(testCase.method, "http://localhost"+testCase.path, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()
			h := NewHealthChecksHandler(source, HealthChecksConfig{BindAddress: "localhost", BindPort: "8080", ReadyPath: "/ready", LivePath: "/live"})
			h.ServeHTTP(w, r)

			t.Logf("HEADERS: %q", w.Header())
			assert.Equal(t, testCase.code, w.Code)
		})
	}
}
