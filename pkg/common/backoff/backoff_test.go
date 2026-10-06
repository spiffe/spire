package backoff

import (
	"testing"
	"time"

	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
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
	inRangeWithFactor(t, expected, _jitter, b)
}

func inRangeWithFactor(t *testing.T, expected time.Duration, factor float64, b BackOff) {
	minInterval := expected - time.Duration(factor*float64(expected))
	maxInterval := expected + time.Duration(factor*float64(expected))
	actualInterval := b.NextBackOff()
	require.GreaterOrEqual(t, actualInterval, minInterval)
	require.LessOrEqual(t, actualInterval, maxInterval)
}

func TestBackOffWithMultiplier(t *testing.T) {
	testInitialInterval := 1000 * time.Millisecond

	mockClk := clock.NewMock(t)
	b := NewBackoff(mockClk, testInitialInterval, WithMultiplier(3))

	expectedResults := []time.Duration{}
	for _, d := range []int{1000, 3000, 9000, 24000, 24000} {
		expectedResults = append(expectedResults, time.Duration(d)*time.Millisecond)
	}

	for _, expected := range expectedResults {
		// Assert that the next backoff falls in the expected range.
		inRange(t, expected, b)
		mockClk.Add(expected)
	}
}

func TestBackOffWithRandomizationFactor(t *testing.T) {
	testInitialInterval := 1000 * time.Millisecond
	testRandomizationFactor := 0.5

	mockClk := clock.NewMock(t)
	b := NewBackoff(mockClk, testInitialInterval, WithRandomizationFactor(testRandomizationFactor))

	expectedResults := []time.Duration{}
	for _, d := range []int{1000, 1500, 2250, 3375} {
		expectedResults = append(expectedResults, time.Duration(d)*time.Millisecond)
	}

	for _, expected := range expectedResults {
		inRangeWithFactor(t, expected, testRandomizationFactor, b)
		mockClk.Add(expected)
	}

	// The configured factor is wider than the default jitter, so over enough
	// draws at least one interval must land outside the default band.
	outsideDefaultBand := false
	for i := 0; i < 200 && !outsideDefaultBand; i++ {
		b.Reset()
		actual := b.NextBackOff()
		deviation := (actual - testInitialInterval).Abs()
		outsideDefaultBand = deviation > time.Duration(_jitter*float64(testInitialInterval))
	}
	require.True(t, outsideDefaultBand, "randomization factor %v was not applied; every interval fell within the default jitter of %v", testRandomizationFactor, _jitter)
}
