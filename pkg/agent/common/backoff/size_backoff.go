package backoff

// SizeLimitedBackOff defines interface for implementing a size based backoff for requests which
// contain number of records to be processed by server.
type SizeLimitedBackOff interface {
	// NextBackOff returns the duration to wait before retrying the operation,
	// or backoff.
	NextBackOff() int

	// Success indicates the backoff implementation that previous request succeeded
	// so that it can adjust backoff accordingly for next request.
	Success()

	// Failure indicates the backoff implementation that previous request failed
	// so that it can adjust backoff accordingly for next request.
	Failure()

	// Reset to initial state.
	Reset()
}

type sizeLimitedBackOff struct {
	currentSize int
	maxSize     int
}

var _ SizeLimitedBackOff = (*sizeLimitedBackOff)(nil)

func (r *sizeLimitedBackOff) NextBackOff() int {
	return r.currentSize
}

func (r *sizeLimitedBackOff) Success() {
	newSize := r.currentSize * 2
	if newSize > r.maxSize {
		newSize = r.maxSize
	}
	r.currentSize = newSize
}

func (r *sizeLimitedBackOff) Failure() {
	newSize := r.currentSize / 2
	if newSize < 1 {
		newSize = 1
	}
	r.currentSize = newSize
}

func (r *sizeLimitedBackOff) Reset() {
	r.currentSize = r.maxSize
}

// NewSizeLimitedBackOff returns a new SizeLimitedBackOff with provided maxRequestSize and lowest request size of 1.
// On Failure the size gets reduced by half and on Success size gets doubled
func NewSizeLimitedBackOff(maxRequestSize int) SizeLimitedBackOff {
	b := &sizeLimitedBackOff{
		maxSize: maxRequestSize,
	}
	b.Reset()

	return b
}
