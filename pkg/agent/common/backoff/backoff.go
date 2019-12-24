package backoff

import (
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/cenkalti/backoff/v3"
)

// BackOff type alias of "github.com/cenkalti/backoff/v3" BackOff, for
// better readability in importing
type BackOff = backoff.BackOff

const (
	_jitter              = 0.10
	_backoffMultiplier   = backoff.DefaultMultiplier
	_maxIntervalMultiple = 24
	_noMaxElapsedTime    = 0
)

// NewBackoff returns a new backoff calculator ready for use. Generalizes all backoffs
// to have the same behavioral pattern, though with different bounds based on given
// interval.
func NewBackoff(clk clock.Clock, interval time.Duration) BackOff {
	b := &backoff.ExponentialBackOff{
		Clock:               clk,
		InitialInterval:     interval,
		RandomizationFactor: _jitter,
		Multiplier:          _backoffMultiplier,
		MaxInterval:         _maxIntervalMultiple * interval,
		MaxElapsedTime:      _noMaxElapsedTime,
	}
	b.Reset()

	return b
}
