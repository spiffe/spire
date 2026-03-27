//go:build linux

package endpoints

import (
	"os"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	// podUIDCacheTTL is the duration for which a resolved pod UID is cached
	// per PID before re-resolving from procfs.
	podUIDCacheTTL = 10 * time.Second
)

// containerInfoPodUIDResolver resolves the pod UID for a given PID by reading
// the process's cgroup information from procfs.
type containerInfoPodUIDResolver struct {
	extractor containerinfo.Extractor
	hclogger  *log.HCLogAdapter
}

func (r *containerInfoPodUIDResolver) GetPodUID(pid int32) string {
	podUID, _, err := r.extractor.GetPodUIDAndContainerID(pid, r.hclogger)
	if err != nil {
		r.hclogger.Debug("Failed to resolve pod UID; falling back to OS UID", telemetry.PID, pid)
		return ""
	}
	return string(podUID)
}

// cachedPodUID stores a resolved pod UID along with its expiration time.
type cachedPodUID struct {
	uid       string
	expiresAt time.Time
}

// cachingPodUIDResolver wraps a podUIDResolver with a per-PID cache to avoid
// repeated procfs reads on every RPC.
type cachingPodUIDResolver struct {
	inner podUIDResolver
	cache sync.Map // map[int32]cachedPodUID
	ttl   time.Duration
	clock clock.Clock
}

func (r *cachingPodUIDResolver) GetPodUID(pid int32) string {
	if entry, ok := r.cache.Load(pid); ok {
		cached := entry.(cachedPodUID)
		if r.clock.Now().Before(cached.expiresAt) {
			return cached.uid
		}
	}
	uid := r.inner.GetPodUID(pid)
	r.cache.Store(pid, cachedPodUID{uid: uid, expiresAt: r.clock.Now().Add(r.ttl)})
	return uid
}

func newPodUIDResolver(logger logrus.FieldLogger) podUIDResolver {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		logger.Debug("KUBERNETES_SERVICE_HOST not set; pod UID resolution disabled")
		return nil
	}
	inner := &containerInfoPodUIDResolver{
		extractor: containerinfo.Extractor{RootDir: "/"},
		hclogger:  log.NewHCLogAdapter(logger, "pod_uid_resolver"),
	}
	return &cachingPodUIDResolver{
		inner: inner,
		ttl:   podUIDCacheTTL,
		clock: clock.New(),
	}
}
