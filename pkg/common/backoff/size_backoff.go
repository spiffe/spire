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
	r.currentSize = min(r.currentSize*2, r.maxSize)
}

func (r *sizeLimitedBackOff) Failure() {
	r.currentSize = max(r.currentSize/2, 1)
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
