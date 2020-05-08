package api

import (
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type JWTSVID struct {
	ID        spiffeid.ID
	Token     string
	ExpiresAt time.Time
	IssuedAt  time.Time
}
