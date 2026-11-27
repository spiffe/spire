package k8s

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// restMapperRefreshCooldown bounds how often a failed object lookup can trigger
// a fresh discovery round. Repeated lookups of objects that truly do not exist
// would otherwise cause a discovery request each time.
const restMapperRefreshCooldown = 30 * time.Second

// refreshableRESTMapper wraps a RESTMapper whose cached discovery information
// can become stale, for example when a CRD stops serving an old version.
// Callers can request a fresh mapper after an object read returns NotFound.
//
// Refresh is rate limited so repeated lookups of objects that truly do not
// exist do not hammer the Kubernetes API server. The generation changes only
// when the mapper is actually replaced, allowing callers to retry only when
// the mapping could have changed.
type refreshableRESTMapper struct {
	mu sync.RWMutex

	mapper    meta.RESTMapper
	newMapper func() (meta.RESTMapper, error)
	gen       uint64

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

func (m *refreshableRESTMapper) generation() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gen
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
	m.gen++
	return nil
}

func (m *refreshableRESTMapper) KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	return m.current().KindFor(resource)
}

func (m *refreshableRESTMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	return m.current().KindsFor(resource)
}

func (m *refreshableRESTMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	return m.current().ResourceFor(input)
}

func (m *refreshableRESTMapper) ResourcesFor(input schema.GroupVersionResource) ([]schema.GroupVersionResource, error) {
	return m.current().ResourcesFor(input)
}

func (m *refreshableRESTMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	return m.current().RESTMapping(gk, versions...)
}

func (m *refreshableRESTMapper) RESTMappings(gk schema.GroupKind, versions ...string) ([]*meta.RESTMapping, error) {
	return m.current().RESTMappings(gk, versions...)
}

func (m *refreshableRESTMapper) ResourceSingularizer(resource string) (string, error) {
	return m.current().ResourceSingularizer(resource)
}
