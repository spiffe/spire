package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBundleCacheChanges(t *testing.T) {
	bundleCache := NewBundleCache(trustDomain1, bundleV1)

	bundleStream := bundleCache.SubscribeToBundleChanges()
	assert.Equal(t, makeBundles(bundleV1), bundleStream.Value())

	bundleCache.Update(makeBundles(bundleV1, otherBundleV1))
	if assert.True(t, bundleStream.HasNext(), "has new bundle value after adding bundle") {
		bundleStream.Next()
		assert.Equal(t, makeBundles(bundleV1, otherBundleV1), bundleStream.Value())
	}

	bundleCache.Update(makeBundles(bundleV1))
	if assert.True(t, bundleStream.HasNext(), "has new bundle value after removing bundle") {
		bundleStream.Next()
		assert.Equal(t, makeBundles(bundleV1), bundleStream.Value())
	}
}

func TestBundleCacheUpdate(t *testing.T) {
	cache := NewBundleCache(trustDomain1, bundleV1)
	stream := cache.SubscribeToBundleChanges()
	assert.Equal(t, makeBundles(bundleV1), stream.Value())

	// Adding a federated bundle is a real change and fires the stream.
	cache.Update(makeBundles(bundleV1, otherBundleV1))
	if assert.True(t, stream.HasNext(), "expected a notification after adding a bundle") {
		stream.Next()
		assert.Equal(t, makeBundles(bundleV1, otherBundleV1), stream.Value())
	}

	// Re-applying the same bundles is a no-op and must NOT fire the stream.
	cache.Update(makeBundles(bundleV1, otherBundleV1))
	assert.False(t, stream.HasNext(), "expected no notification when nothing changed")

	// Removing the federated bundle is a real change and fires the stream.
	cache.Update(makeBundles(bundleV1))
	if assert.True(t, stream.HasNext(), "expected a notification after removing a bundle") {
		stream.Next()
		assert.Equal(t, makeBundles(bundleV1), stream.Value())
	}
}

// TestBundleCacheUpdateOwnTrustDomain asserts that a change to the agent's own
// trust domain bundle is applied and fires the stream.
func TestBundleCacheUpdateOwnTrustDomain(t *testing.T) {
	cache := NewBundleCache(trustDomain1, bundleV1)
	stream := cache.SubscribeToBundleChanges()
	assert.Equal(t, bundleV1, cache.Bundle())

	// Rotating the agent's own trust domain bundle is a real change.
	cache.Update(makeBundles(bundleV2))
	if assert.True(t, stream.HasNext(), "expected a notification after the own bundle changed") {
		stream.Next()
	}
	assert.Equal(t, bundleV2, cache.Bundle())
	assert.Equal(t, makeBundles(bundleV2), cache.Bundles())

	// Re-applying the same bundle is a no-op and must NOT fire the stream.
	cache.Update(makeBundles(bundleV2))
	assert.False(t, stream.HasNext(), "expected no notification when the own bundle is unchanged")
	assert.Equal(t, bundleV2, cache.Bundle())
}

// TestBundleCacheUpdatePreservesOwnTrustDomain asserts that the agent's own
// trust domain bundle is never dropped, even if the server omits it from an
// update, since it is required to authenticate the server.
func TestBundleCacheUpdatePreservesOwnTrustDomain(t *testing.T) {
	cache := NewBundleCache(trustDomain1, bundleV1)
	stream := cache.SubscribeToBundleChanges()

	// Seed with a federated bundle alongside the agent's own bundle.
	cache.Update(makeBundles(bundleV1, otherBundleV1))
	if assert.True(t, stream.HasNext()) {
		stream.Next()
	}

	// An update that omits the agent's own trust domain bundle must retain it.
	// Here only the federated bundle is present in the update.
	cache.Update(makeBundles(otherBundleV1))

	// The own trust domain bundle is still available...
	assert.Equal(t, bundleV1, cache.Bundle())
	// ...and the full set is unchanged, so no notification should fire.
	assert.Equal(t, makeBundles(bundleV1, otherBundleV1), cache.Bundles())
	assert.False(t, stream.HasNext(), "expected no notification when the effective bundle set is unchanged")

	// A genuine change to a federated bundle still fires while retaining the
	// preserved own trust domain bundle.
	cache.Update(makeBundles(otherBundleV2))
	if assert.True(t, stream.HasNext(), "expected a notification when a federated bundle changed") {
		stream.Next()
	}
	assert.Equal(t, bundleV1, cache.Bundle())
	assert.Equal(t, makeBundles(bundleV1, otherBundleV2), cache.Bundles())
}
