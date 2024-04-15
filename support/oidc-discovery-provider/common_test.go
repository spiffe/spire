package main

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	ec256Pubkey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiSt7S4ih6QLodw9wf+zdPV8bmAlD
JBCRRy24/UAZY70ZviCRAJ4ePscJtnN1y1wDH13GgOAL2y52xIbtkshYmw==
-----END PUBLIC KEY-----`))
	ec256PubkeyPKIX, _ = x509.MarshalPKIXPublicKey(ec256Pubkey)
)

type FakeKeySetSource struct {
	mu       sync.Mutex
	jwks     *jose.JSONWebKeySet
	modTime  time.Time
	pollTime time.Time
}

func (s *FakeKeySetSource) SetKeySet(jwks *jose.JSONWebKeySet, modTime time.Time, pollTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwks = jwks
	s.modTime = modTime
	s.pollTime = pollTime
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

func (s *FakeKeySetSource) LastSuccessfulPoll() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pollTime
}
