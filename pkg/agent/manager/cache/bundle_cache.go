package cache

import (
	"github.com/imkira/go-observer"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type BundleCache struct {
	trustDomain spiffeid.TrustDomain
	bundles     observer.Property
}

func NewBundleCache(trustDomain spiffeid.TrustDomain, bundle *Bundle) *BundleCache {
	bundles := map[spiffeid.TrustDomain]*Bundle{
		trustDomain: bundle,
	}
	return &BundleCache{
		trustDomain: trustDomain,
		bundles:     observer.NewProperty(bundles),
	}
}

func (c *BundleCache) Update(bundles map[spiffeid.TrustDomain]*Bundle) {
	// the bundle map must be copied so that the source can be mutated
	// afterwards.
	c.bundles.Update(copyBundleMap(bundles))
}

func (c *BundleCache) Bundle() *Bundle {
	return c.Bundles()[c.trustDomain]
}

func (c *BundleCache) Bundles() map[spiffeid.TrustDomain]*Bundle {
	return c.bundles.Value().(map[spiffeid.TrustDomain]*Bundle)
}

func (c *BundleCache) SubscribeToBundleChanges() *BundleStream {
	return NewBundleStream(c.bundles.Observe())
}

// Wraps an observer stream to provide a type safe interface
type BundleStream struct {
	stream observer.Stream
}

func NewBundleStream(stream observer.Stream) *BundleStream {
	return &BundleStream{
		stream: stream,
	}
}

// Value returns the current value for this stream.
func (b *BundleStream) Value() map[spiffeid.TrustDomain]*Bundle {
	return b.stream.Value().(map[spiffeid.TrustDomain]*Bundle)
}

// Changes returns the channel that is closed when a new value is available.
func (b *BundleStream) Changes() chan struct{} {
	return b.stream.Changes()
}

// Next advances this stream to the next state.
// You should never call this unless Changes channel is closed.
func (b *BundleStream) Next() map[spiffeid.TrustDomain]*Bundle {
	value, _ := b.stream.Next().(map[spiffeid.TrustDomain]*Bundle)
	return value
}

// HasNext checks whether there is a new value available.
func (b *BundleStream) HasNext() bool {
	return b.stream.HasNext()
}

// WaitNext waits for Changes to be closed, advances the stream and returns
// the current value.
func (b *BundleStream) WaitNext() map[spiffeid.TrustDomain]*Bundle {
	value, _ := b.stream.WaitNext().(map[spiffeid.TrustDomain]*Bundle)
	return value
}

// Clone creates a new independent stream from this one but sharing the same
// Property. Updates to the property will be reflected in both streams but
// they may have different values depending on when they advance the stream
// with Next.
func (b *BundleStream) Clone() *BundleStream {
	return &BundleStream{
		stream: b.stream.Clone(),
	}
}

// copyBundleMap does a shallow copy of the bundle map.
func copyBundleMap(bundles map[spiffeid.TrustDomain]*Bundle) map[spiffeid.TrustDomain]*Bundle {
	if bundles == nil {
		return nil
	}

	out := make(map[spiffeid.TrustDomain]*Bundle, len(bundles))
	for key, bundle := range bundles {
		out[key] = bundle
	}
	return out
}
