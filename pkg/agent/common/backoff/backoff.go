package backoff

import (
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/cenkalti/backoff/v4"
)

// BackOff type alias of "github.com/cenkalti/backoff/v4" BackOff, for
// better readability in importing
type BackOff = backoff.BackOff

const (
	_jitter              = 0.10
	_backoffMultiplier   = backoff.DefaultMultiplier
	_maxIntervalMultiple = 24
	_noMaxElapsedTime    = 0
)

// Option allows customization of the backoff.ExponentialBackOff
type Option interface {
	applyOption(*backoff.ExponentialBackOff)
}

// NewBackoff returns a new backoff calculator ready for use. Generalizes all backoffs
// to have the same behavioral pattern, though with different bounds based on given
// interval.
func NewBackoff(clk clock.Clock, interval time.Duration, opts ...Option) BackOff {
	b := &backoff.ExponentialBackOff{
		Clock:               clk,
		InitialInterval:     interval,
		RandomizationFactor: _jitter,
		Multiplier:          _backoffMultiplier,
		MaxInterval:         _maxIntervalMultiple * interval,
		MaxElapsedTime:      _noMaxElapsedTime,
	}
	for _, opt := range opts {
		opt.applyOption(b)
	}
	b.Reset()

	return b
}

// WithMaxInterval returns maxInterval backoff option to override the MaxInterval
func WithMaxInterval(maxInterval time.Duration) Option {
	return backoffOption{maxInterval: maxInterval}
}

type backoffOption struct {
	maxInterval time.Duration
}

func (b backoffOption) applyOption(bo *backoff.ExponentialBackOff) {
	bo.MaxInterval = b.maxInterval
}
