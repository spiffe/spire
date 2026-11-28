package k8s

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestRefreshableRESTMapperRefresh(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "example.org", Version: "v1", Kind: "Widget"}
	gvr := schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: "widgets"}

	refreshes := 0
	mapper := newRefreshableRESTMapper(meta.NewDefaultRESTMapper(nil), func() (meta.RESTMapper, error) {
		refreshes++
		return testRESTMapperFor(gvk), nil
	})

	_, err := mapper.KindFor(gvr)
	require.Error(t, err)
	require.True(t, meta.IsNoMatchError(err))
	require.Equal(t, uint64(0), mapper.generation())
	require.Equal(t, 0, refreshes)

	generation := mapper.generation()
	require.NoError(t, mapper.refreshAfterMiss())
	require.NotEqual(t, generation, mapper.generation())
	require.Equal(t, 1, refreshes)

	got, err := mapper.KindFor(gvr)
	require.NoError(t, err)
	require.Equal(t, gvk, got)
}

func TestRefreshableRESTMapperRateLimitsRefresh(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "example.org", Version: "v1", Kind: "Widget"}
	now := time.Unix(0, 0)

	refreshes := 0
	mapper := newRefreshableRESTMapper(meta.NewDefaultRESTMapper(nil), func() (meta.RESTMapper, error) {
		refreshes++
		return testRESTMapperFor(gvk), nil
	})
	mapper.now = func() time.Time { return now }
	mapper.refreshCooldown = time.Minute

	require.NoError(t, mapper.refreshAfterMiss())
	require.Equal(t, 1, refreshes)
	generation := mapper.generation()

	require.NoError(t, mapper.refreshAfterMiss())
	require.Equal(t, 1, refreshes, "refresh should be rate limited")
	require.Equal(t, generation, mapper.generation())

	now = now.Add(time.Minute)
	require.NoError(t, mapper.refreshAfterMiss())
	require.Equal(t, 2, refreshes, "refresh should be allowed after the cooldown")
	require.NotEqual(t, generation, mapper.generation())
}

func TestRefreshableRESTMapperRefreshIfStale(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "example.org", Version: "v1", Kind: "Widget"}
	now := time.Unix(0, 0)

	refreshes := 0
	mapper := newRefreshableRESTMapper(meta.NewDefaultRESTMapper(nil), func() (meta.RESTMapper, error) {
		refreshes++
		return testRESTMapperFor(gvk), nil
	})
	mapper.now = func() time.Time { return now }
	mapper.lastRefresh = now
	mapper.refreshCooldown = 0

	require.NoError(t, mapper.refreshIfStale(time.Minute))
	require.Equal(t, 0, refreshes)
	generation := mapper.generation()

	now = now.Add(30 * time.Second)
	require.NoError(t, mapper.refreshIfStale(time.Minute))
	require.Equal(t, 0, refreshes)

	now = now.Add(30 * time.Second)
	require.NoError(t, mapper.refreshIfStale(time.Minute))
	require.Equal(t, 1, refreshes)
	require.NotEqual(t, generation, mapper.generation())

	generation = mapper.generation()
	now = now.Add(2 * time.Minute)
	require.NoError(t, mapper.refreshIfStale(2*time.Minute))
	require.Equal(t, 2, refreshes)
	require.NotEqual(t, generation, mapper.generation())
}

func TestRefreshableRESTMapperRefreshIfStaleKeepsOldMapperOnFailure(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "example.org", Version: "v1", Kind: "Widget"}
	gvr := schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: "widgets"}
	now := time.Unix(0, 0)

	fail := true
	mapper := newRefreshableRESTMapper(testRESTMapperFor(gvk), func() (meta.RESTMapper, error) {
		if fail {
			return nil, errors.New("discovery unavailable")
		}
		return testRESTMapperFor(gvk), nil
	})
	mapper.now = func() time.Time { return now }
	mapper.lastRefresh = now

	now = now.Add(time.Minute)
	require.Error(t, mapper.refreshIfStale(time.Minute))
	require.Equal(t, uint64(0), mapper.generation())

	// The previous mapper is still usable while the API server is unavailable.
	_, err := mapper.KindFor(gvr)
	require.NoError(t, err)

	// The failed attempt is rate limited instead of retried on every lookup.
	require.NoError(t, mapper.refreshIfStale(time.Minute))

	now = now.Add(time.Minute)
	fail = false
	require.NoError(t, mapper.refreshIfStale(time.Minute))
	require.Equal(t, uint64(1), mapper.generation())
}

func TestRefreshableRESTMapperRefreshDoesNotBlockLookups(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "example.org", Version: "v1", Kind: "Widget"}
	gvr := schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: "widgets"}
	now := time.Unix(0, 0)

	started := make(chan struct{})
	release := make(chan struct{})
	mapper := newRefreshableRESTMapper(testRESTMapperFor(gvk), func() (meta.RESTMapper, error) {
		close(started)
		<-release
		return testRESTMapperFor(gvk), nil
	})
	mapper.now = func() time.Time { return now }
	mapper.lastRefresh = now.Add(-time.Minute)

	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- mapper.refreshIfStale(time.Minute)
	}()
	<-started

	lookupDone := make(chan error, 1)
	go func() {
		_, err := mapper.KindFor(gvr)
		lookupDone <- err
	}()

	select {
	case err := <-lookupDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("lookup blocked while the mapper was refreshing")
	}

	close(release)
	require.NoError(t, <-refreshDone)
	require.Equal(t, uint64(1), mapper.generation())
}

func testRESTMapperFor(gvk schema.GroupVersionKind) meta.RESTMapper {
	resource := schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: "widgets",
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{gvk.GroupVersion()})
	mapper.AddSpecific(gvk, resource, schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: "widget",
	}, meta.RESTScopeNamespace)
	return mapper
}
