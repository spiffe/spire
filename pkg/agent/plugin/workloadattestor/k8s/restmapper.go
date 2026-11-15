package k8s

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// restMapperRefreshCooldown bounds how often a failed lookup can trigger a
// fresh discovery round. Genuinely unknown resources would otherwise cause a
// discovery request on every lookup.
const restMapperRefreshCooldown = 30 * time.Second

// refreshableRESTMapper wraps a RESTMapper whose cached discovery information
// can become stale, for example when a CRD starts serving a new version or
// stops serving an old one. A NoMatch result triggers a refresh and one retry;
// callers can also refresh explicitly when an object read returns NotFound.
//
// Refresh is rate limited so repeated lookups of resources that truly do not
// exist do not hammer the Kubernetes API server.
type refreshableRESTMapper struct {
	mu sync.RWMutex

	mapper    meta.RESTMapper
	newMapper func() (meta.RESTMapper, error)

	refreshCooldown time.Duration
	lastMissRefresh time.Time
	now             func() time.Time
}

func newRefreshableRESTMapper(mapper meta.RESTMapper, newMapper func() (meta.RESTMapper, error)) *refreshableRESTMapper {
	return &refreshableRESTMapper{
		mapper:          mapper,
		newMapper:       newMapper,
		refreshCooldown: restMapperRefreshCooldown,
		now:             time.Now,
	}
}

func (m *refreshableRESTMapper) current() meta.RESTMapper {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mapper
}

// refreshAfterMiss replaces the mapper with a fresh one unless a refresh was
// already attempted within the cooldown window.
func (m *refreshableRESTMapper) refreshAfterMiss() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if !m.lastMissRefresh.IsZero() && now.Sub(m.lastMissRefresh) < m.refreshCooldown {
		return nil
	}
	mapper, err := m.newMapper()
	if err != nil {
		return err
	}
	m.lastMissRefresh = now
	m.mapper = mapper
	return nil
}

func (m *refreshableRESTMapper) retryOnNoMatch(lookup func(meta.RESTMapper) error) error {
	err := lookup(m.current())
	if err == nil || !meta.IsNoMatchError(err) {
		return err
	}
	if refreshErr := m.refreshAfterMiss(); refreshErr != nil {
		return refreshErr
	}
	return lookup(m.current())
}

func (m *refreshableRESTMapper) KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	var gvk schema.GroupVersionKind
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		gvk, err = mapper.KindFor(resource)
		return err
	})
	return gvk, err
}

func (m *refreshableRESTMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	var gvks []schema.GroupVersionKind
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		gvks, err = mapper.KindsFor(resource)
		return err
	})
	return gvks, err
}

func (m *refreshableRESTMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	var gvr schema.GroupVersionResource
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		gvr, err = mapper.ResourceFor(input)
		return err
	})
	return gvr, err
}

func (m *refreshableRESTMapper) ResourcesFor(input schema.GroupVersionResource) ([]schema.GroupVersionResource, error) {
	var gvrs []schema.GroupVersionResource
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		gvrs, err = mapper.ResourcesFor(input)
		return err
	})
	return gvrs, err
}

func (m *refreshableRESTMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	var mapping *meta.RESTMapping
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		mapping, err = mapper.RESTMapping(gk, versions...)
		return err
	})
	return mapping, err
}

func (m *refreshableRESTMapper) RESTMappings(gk schema.GroupKind, versions ...string) ([]*meta.RESTMapping, error) {
	var mappings []*meta.RESTMapping
	err := m.retryOnNoMatch(func(mapper meta.RESTMapper) error {
		var err error
		mappings, err = mapper.RESTMappings(gk, versions...)
		return err
	})
	return mappings, err
}

func (m *refreshableRESTMapper) ResourceSingularizer(resource string) (string, error) {
	return m.current().ResourceSingularizer(resource)
}
