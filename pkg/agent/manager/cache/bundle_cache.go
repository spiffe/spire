package cache

import (
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/observer"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
)

type Bundle = spiffebundle.Bundle

var _ x509bundle.Source = (*BundleCache)(nil)

type BundleCache struct {
	trustDomain  spiffeid.TrustDomain
	clk          clock.Clock
	maxStaleness time.Duration
	metrics      telemetry.Metrics
	log          logrus.FieldLogger

	// dispatchMu serializes state transitions with observer publication. A timer
	// firing concurrently with a successful sync can therefore never publish an
	// older view after the newly confirmed view.
	dispatchMu sync.Mutex
	mu         sync.RWMutex

	// source contains the accepted bundle set. It starts with the bootstrap
	// bundle; confirmedAt and stale apply only to federated trust domains.
	source      map[spiffeid.TrustDomain]*Bundle
	confirmedAt map[spiffeid.TrustDomain]time.Time
	stale       map[spiffeid.TrustDomain]struct{}
	// bundles is the currently visible set. It always contains the agent's
	// own trust-domain bundle and omits federated bundles that are stale.
	bundles observer.Property
	wake    chan struct{}
}

func NewBundleCache(trustDomain spiffeid.TrustDomain, bundle *Bundle) *BundleCache {
	return NewBundleCacheWithConfig(BundleCacheConfig{
		TrustDomain: trustDomain,
		Bundle:      bundle,
	})
}

// NewBundleCacheWithConfig constructs the manager's shared bundle source. See
// BundleCacheConfig for freshness semantics.
func NewBundleCacheWithConfig(config BundleCacheConfig) *BundleCache {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	if config.Metrics == nil {
		config.Metrics = telemetry.Blackhole{}
	}

	bundles := map[spiffeid.TrustDomain]*Bundle{
		config.TrustDomain: config.Bundle,
	}
	c := &BundleCache{
		trustDomain:  config.TrustDomain,
		clk:          config.Clock,
		maxStaleness: config.MaxStaleness,
		metrics:      config.Metrics,
		log:          config.Log,
		source:       copyBundleMap(bundles),
		confirmedAt:  make(map[spiffeid.TrustDomain]time.Time),
		stale:        make(map[spiffeid.TrustDomain]struct{}),
		bundles:      observer.NewProperty(bundles),
		wake:         make(chan struct{}, 1),
	}
	telemetry_agent.InitializeFederatedBundleTransitionCounters(c.metrics)
	c.emitStateMetrics(0, 0)
	return c
}

// Update confirms the complete bundle set returned by a successful server
// response. Reconfirming byte-identical bundles refreshes their deadlines but
// does not publish a bundle update unless their visibility changes.
func (c *BundleCache) Update(bundles map[spiffeid.TrustDomain]*Bundle) {
	c.confirm(bundles, c.clk.Now())
}

func bundleMapsEqual(a, b map[spiffeid.TrustDomain]*Bundle) bool {
	if len(a) != len(b) {
		return false
	}
	for td, bundleA := range a {
		bundleB, ok := b[td]
		if !ok || !bundleA.Equal(bundleB) {
			return false
		}
	}
	return true
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

func (c *BundleCache) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	bundles := c.Bundles()
	bundle, ok := bundles[trustDomain]
	if !ok {
		return nil, fmt.Errorf("bundle for trust domain %q not found", trustDomain)
	}
	return bundle.X509Bundle(), nil
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
// Property. Updates to the property will be reflected in both streams, but
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
	maps.Copy(out, bundles)
	return out
}
