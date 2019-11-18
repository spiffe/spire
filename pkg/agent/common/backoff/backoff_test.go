package backoff

import (
	"testing"
	"time"

	v3backoff "github.com/cenkalti/backoff/v3"
	"github.com/spiffe/spire/test/clock"
)

// modified from `TestBackoff` in "github.com/cenkalti/backoff/v3", narrowed down to specific usage
func TestBackOff(t *testing.T) {
	testInitialInterval := 6400 * time.Millisecond

	mockClk := clock.NewMock(t)
	b := NewBackoff(mockClk, testInitialInterval)

	var expectedResults = []time.Duration{6400, 9600, 14400, 21600, 32400, 48600, 72900, 109350, 153600, 153600}
	for i, d := range expectedResults {
		expectedResults[i] = d * time.Millisecond
	}

	for _, expected := range expectedResults {
		// Assert that the next backoff falls in the expected range.
		inRange(t, expected, b)
		mockClk.Add(expected)
	}

	// assert reset works as expected
	b.Reset()
	inRange(t, expectedResults[0], b)
}

func inRange(t *testing.T, expected time.Duration, b v3backoff.BackOff) {
	var minInterval = expected - time.Duration(_jitter*float64(expected))
	var maxInterval = expected + time.Duration(_jitter*float64(expected))
	var actualInterval = b.NextBackOff()
	if !(minInterval <= actualInterval && actualInterval <= maxInterval) {
		t.Error("error")
	}
}
