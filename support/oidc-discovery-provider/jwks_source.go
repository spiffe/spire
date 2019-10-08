package main

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

type JWKSSource interface {
	// FetchJWKS returns the key set and modified time.
	FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool)

	// Close closes the source.
	Close() error
}
