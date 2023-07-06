package backoff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestSizeBackOff(t *testing.T) {
	t.Run("max request size does not go above configured maximum", func(t *testing.T) {
		maxRequestSize := 1000
		b := NewSizeLimitedBackOff(maxRequestSize)

		// Initial backoff value should be equal to the maxRequestSize
		assert.Equal(t, maxRequestSize, b.NextBackOff())

		// After multiple successes, the backoff value should cap at maxRequestSize
		b.Success()
		assert.Equal(t, maxRequestSize, b.NextBackOff())
		b.Success()
		assert.Equal(t, maxRequestSize, b.NextBackOff())
	})
	t.Run("min request size does not go below 1", func(t *testing.T) {
		// validate lower limit
		maxRequestSize := 5
		b := NewSizeLimitedBackOff(maxRequestSize)
		assert.Equal(t, maxRequestSize, b.NextBackOff())

		b.Failure()
		assert.Equal(t, 2, b.NextBackOff())
		b.Failure()
		assert.Equal(t, 1, b.NextBackOff())

		// backoff value should not go below 1
		b.Failure()
		assert.Equal(t, 1, b.NextBackOff())
	})
	t.Run("backoff updates on Failure, Success and Reset", func(t *testing.T) {
		maxRequestSize := 1000
		b := NewSizeLimitedBackOff(maxRequestSize)
		// After a failure, the backoff value should be halved
		b.Failure()
		assert.Equal(t, maxRequestSize/2, b.NextBackOff())

		// After multiple failures, the backoff value should keep halving
		b.Failure()
		b.Failure()
		assert.Equal(t, maxRequestSize/8, b.NextBackOff())

		// After success backoff value should keep doubling
		b.Success()
		assert.Equal(t, maxRequestSize/4, b.NextBackOff())
		b.Success()
		assert.Equal(t, maxRequestSize/2, b.NextBackOff())

		// Reset should set the backoff value back to the initial maxRequestSize
		b.Reset()
		assert.Equal(t, maxRequestSize, b.NextBackOff())
	})
}
