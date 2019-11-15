package backoff

import (
	"time"

	"github.com/andres-erbsen/clock"
	v3backoff "github.com/cenkalti/backoff/v3"
)

const (
	_jitter              = 0.10
	_backoffMultiplier   = v3backoff.DefaultMultiplier
	_maxIntervalMultiple = 24
	_noMaxElapsedTime    = 0
)

// NewBackoff returns a new backoff calculator ready for use. Generalizes all backoffs
// to have the same behaviorial pattern, though with different bounds based on given
// interval.
func NewBackoff(clk clock.Clock, interval time.Duration) v3backoff.BackOff {
	b := &v3backoff.ExponentialBackOff{
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
