package cache

import (
	"github.com/imkira/go-observer"
)

type BundleCache struct {
	trustDomainID string
	bundles       observer.Property
}

func NewBundleCache(trustDomainID string, bundle *Bundle) *BundleCache {
	bundles := map[string]*Bundle{
		trustDomainID: bundle,
	}
	return &BundleCache{
		trustDomainID: trustDomainID,
		bundles:       observer.NewProperty(bundles),
	}
}

func (c *BundleCache) Update(bundles map[string]*Bundle) {
	// the bundle map must be copied so that the source can be mutated
	// afterwards.
	c.bundles.Update(copyBundleMap(bundles))
}

func (c *BundleCache) Bundle() *Bundle {
	return c.Bundles()[c.trustDomainID]
}

func (c *BundleCache) Bundles() map[string]*Bundle {
	return c.bundles.Value().(map[string]*Bundle)
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
func (b *BundleStream) Value() map[string]*Bundle {
	value, _ := b.stream.Value().(map[string]*Bundle)
	return value
}

// Changes returns the channel that is closed when a new value is available.
func (b *BundleStream) Changes() chan struct{} {
	return b.stream.Changes()
}

// Next advances this stream to the next state.
// You should never call this unless Changes channel is closed.
func (b *BundleStream) Next() map[string]*Bundle {
	value, _ := b.stream.Next().(map[string]*Bundle)
	return value
}

// HasNext checks whether there is a new value available.
func (b *BundleStream) HasNext() bool {
	return b.stream.HasNext()
}

// WaitNext waits for Changes to be closed, advances the stream and returns
// the current value.
func (b *BundleStream) WaitNext() map[string]*Bundle {
	value, _ := b.stream.WaitNext().(map[string]*Bundle)
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
func copyBundleMap(bundles map[string]*Bundle) map[string]*Bundle {
	if bundles == nil {
		return nil
	}

	out := make(map[string]*Bundle, len(bundles))
	for key, bundle := range bundles {
		out[key] = bundle
	}
	return out
}
