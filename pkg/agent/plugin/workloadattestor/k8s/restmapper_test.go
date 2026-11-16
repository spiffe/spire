package k8s

import (
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
