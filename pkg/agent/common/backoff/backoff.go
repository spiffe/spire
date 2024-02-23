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
	Stop                 = backoff.Stop
)

// Option allows customization of the backoff.ExponentialBackOff
type Options interface {
	applyOptions(*backoff.ExponentialBackOff)
}

// NewBackoff returns a new backoff calculator ready for use. Generalizes all backoffs
// to have the same behavioral pattern, though with different bounds based on given
// interval.
func NewBackoff(clk clock.Clock, interval time.Duration, opts ...Options) BackOff {
	b := &backoff.ExponentialBackOff{
		Clock:               clk,
		InitialInterval:     interval,
		RandomizationFactor: _jitter,
		Multiplier:          _backoffMultiplier,
		MaxInterval:         _maxIntervalMultiple * interval,
		MaxElapsedTime:      _noMaxElapsedTime,
		Stop:                backoff.Stop,
	}
	for _, opt := range opts {
		opt.applyOptions(b)
	}
	b.Reset()

	return b
}

// WithMaxInterval returns maxInterval backoff option to override the MaxInterval
func WithMaxInterval(maxInterval time.Duration) Options {
	return backoffOptions{maxInterval: maxInterval}
}

// WithMaxElapsedTime returns maxElapsedTime backoff option to override the MaxElapsedTime
func WithMaxElapsedTime(maxElapsedTime time.Duration) Options {
	return backoffOptions{maxElapsedTime: maxElapsedTime}
}

type backoffOptions struct {
	maxInterval    time.Duration
	maxElapsedTime time.Duration
}

func (b backoffOptions) applyOptions(bo *backoff.ExponentialBackOff) {
	if b.maxInterval != 0 {
		bo.MaxInterval = b.maxInterval
	}
	if b.maxElapsedTime != 0 {
		bo.MaxElapsedTime = b.maxElapsedTime
	}
}
