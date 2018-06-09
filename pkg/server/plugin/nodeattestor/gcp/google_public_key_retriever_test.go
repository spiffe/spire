package gcp

import (
	"crypto/x509"
	"sync"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
)

func TestSuccesfullyRetrieveGooglePublicKeys(t *testing.T) {
	retriever := &googlePublicKeyRetriever{
		certificates: make(map[string]*x509.Certificate),
		mtx:          &sync.Mutex{},
	}

	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = "1923397381d9574bb873202a90c32b7ceeaed027"

	key, err := retriever.retrieveKey(token)
	require.NotNil(t, key)
	require.NoError(t, err)
}
