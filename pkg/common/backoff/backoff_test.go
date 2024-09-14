package backoff

import (
	"testing"
	"time"

	"github.com/spiffe/spire/test/clock"
)

// modified from `TestBackoff` in "github.com/cenkalti/backoff/v4", narrowed down to specific usage
func TestBackOff(t *testing.T) {
	testInitialInterval := 6400 * time.Millisecond

	mockClk := clock.NewMock(t)
	b := NewBackoff(mockClk, testInitialInterval)

	expectedResults := []time.Duration{}
	for _, d := range []int{6400, 9600, 14400, 21600, 32400, 48600, 72900, 109350, 153600, 153600} {
		expectedResults = append(expectedResults, time.Duration(d)*time.Millisecond)
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

func TestBackOffWithMaxInterval(t *testing.T) {
	testInitialInterval := 6400 * time.Millisecond

	mockClk := clock.NewMock(t)
	b := NewBackoff(mockClk, testInitialInterval, WithMaxInterval(33000*time.Millisecond))

	expectedResults := []time.Duration{}
	for _, d := range []int{6400, 9600, 14400, 21600, 32400, 33000, 33000} {
		expectedResults = append(expectedResults, time.Duration(d)*time.Millisecond)
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

func inRange(t *testing.T, expected time.Duration, b BackOff) {
	minInterval := expected - time.Duration(_jitter*float64(expected))
	maxInterval := expected + time.Duration(_jitter*float64(expected))
	actualInterval := b.NextBackOff()
	if !(minInterval <= actualInterval && actualInterval <= maxInterval) {
		t.Error("error")
	}
}
