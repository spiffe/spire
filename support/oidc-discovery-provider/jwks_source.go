package main

import (
	"time"

	"github.com/go-jose/go-jose/v3"
)

type JWKSSource interface {
	// FetchJWKS returns the key set and modified time.
	FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool)

	// Close closes the source.
	Close() error

	// LastSuccessfulPoll returns the time of the last successful poll of the JWKS from the source, or a zero value if
	// there hasn't been a successful poll yet.
	LastSuccessfulPoll() time.Time
}
