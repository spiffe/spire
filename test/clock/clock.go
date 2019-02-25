package clock

import (
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"go.uber.org/atomic"
)

// Clock is a clock
type Clock clock.Clock

// New returns a Clock backed by a realtime clock
func New() Clock {
	return clock.New()
}

// Mock is a mock clock that can be precisely controlled
type Mock struct {
	*clock.Mock
	t           testing.TB
	afterC      chan struct{}
	tickerC     chan struct{}
	tickerCount atomic.Uint32
	sleepC      chan struct{}
}

// NewMock creates a mock clock which can be precisely controlled
func NewMock(t testing.TB) *Mock {
	m := &Mock{
		Mock:    clock.NewMock(),
		t:       t,
		afterC:  make(chan struct{}, 1),
		tickerC: make(chan struct{}, 1),
		sleepC:  make(chan struct{}, 1),
	}

	// TLS verification is being done using a realtime clock so we set the mock clock to
	// the current time, truncated to a second which is the granularity available to asn1.
	// This ensures that when tests create a certificate with a lifetime of 3 seconds, it
	// is exactly 3 seconds (relative to the mock clock).
	//
	// TODO: plumb the clock into the TLS configs. (Clock).Now should be passed to "crypto/tls".(Config).Time
	// and then this can be removed as a clock could be use with a zero value at that point.
	m.Set(time.Now().Truncate(time.Second))
	return m
}

// WaitForAfter waits up to the specified timeout for After to be called on the clock.
func (m *Mock) WaitForAfter(timeout time.Duration, format string, args ...interface{}) {
	select {
	case <-m.afterC:
	case <-time.After(timeout):
		m.t.Fatalf(format, args...)
	}
}

// WaitForTicker waits up to the specified timeout for a Ticker to be created from the clock.
func (m *Mock) WaitForTicker(timeout time.Duration, format string, args ...interface{}) {
	m.WaitForTickerMulti(timeout, 1, format, args...)
	return
}

func (m *Mock) WaitForTickerMulti(timeout time.Duration, count int, format string, args ...interface{}) {
	deadlineChan := time.After(timeout)
	for {
		select {
		case <-m.tickerC:
			if m.tickerCount.Load() >= uint32(count) {
				m.tickerCount.Sub(uint32(count))
				return
			}
		case <-deadlineChan:
			m.t.Fatalf(format, args...)
		}
	}
}

// WaitForSleep waits up to the specified timeout for a sleep to begin using the clock.
func (m *Mock) WaitForSleep(timeout time.Duration, format string, args ...interface{}) {
	select {
	case <-m.sleepC:
	case <-time.After(timeout):
		m.t.Fatalf(format, args...)
	}
}

// After waits for the duration to elapse and then sends the current time on the returned channel.
func (m *Mock) After(d time.Duration) <-chan time.Time {
	c := m.Mock.After(d)
	select {
	case m.afterC <- struct{}{}:
	default:
	}

	return c
}

// Ticker returns a new Ticker containing a channel that will send the time with a period specified by the duration argument.
func (m *Mock) Ticker(d time.Duration) *clock.Ticker {
	c := m.Mock.Ticker(d)
	m.tickerCount.Inc()
	select {
	case m.tickerC <- struct{}{}:
	default:
	}

	return c
}

// Sleep pauses the current goroutine for at least the duration d
func (m *Mock) Sleep(d time.Duration) {
	timer := m.Mock.Timer(d)
	select {
	case m.sleepC <- struct{}{}:
	default:
	}
	<-timer.C
}
