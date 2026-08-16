package main

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
)

type JWKSSource interface {
	// FetchJWKS returns the key set and modified time.
	FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool)

	// FetchBundle returns the full SPIFFE trust bundle and modified time.
	FetchBundle() (*spiffebundle.Bundle, time.Time, bool)

	// Close closes the source.
	Close() error

	// LastSuccessfulPoll returns the time of the last successful poll of the JWKS from the source, or a zero value if
	// there hasn't been a successful poll yet.
	LastSuccessfulPoll() time.Time
}
