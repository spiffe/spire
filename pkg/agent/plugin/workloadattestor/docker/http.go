package docker

import (
	"net/http"

	"golang.org/x/time/rate"
)

// default number of requests per second
const defaultRateLimit = 100

func newHTTPClient() *http.Client {
	client := &http.Client{}
	client.Transport = &roundtripper{
		inner:   http.DefaultTransport,
		limiter: rate.NewLimiter(rate.Limit(defaultRateLimit), 1),
	}
	return client
}

type roundtripper struct {
	inner   http.RoundTripper
	limiter *rate.Limiter
}

func (rt *roundtripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := rt.limiter.Wait(r.Context()); err != nil {
		return nil, err
	}
	return rt.inner.RoundTrip(r)
}
