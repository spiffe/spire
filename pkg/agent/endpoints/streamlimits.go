package endpoints

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WorkloadAPIStreamStats describes admitted and waiting streams on one endpoint.
type WorkloadAPIStreamStats struct {
	Active     int
	Pending    int
	PoolActive map[string]int
}

// WorkloadStreamLimiter coordinates active capacity and pending admissions.
type WorkloadStreamLimiter struct {
	mu        sync.Mutex
	limits    WorkloadAPIStreamLimitsConfig
	active    map[string]map[string]int
	workloads map[string]int
	total     int
	pending   []*streamWaiter
	metrics   telemetry.Metrics
	groups    map[string]map[selector.Selector]struct{}
	pools     []streamPool
}

type streamPool struct {
	config    WorkloadAPIStreamPoolConfig
	selectors []selector.Selector
	active    int
}

func (p *streamPool) matches(selectors map[selector.Selector]struct{}) bool {
	for _, required := range p.selectors {
		if _, ok := selectors[required]; !ok {
			return false
		}
	}
	return true
}

type streamWaiter struct {
	ctx       context.Context
	method    string
	key       string
	selectors map[selector.Selector]struct{}
	ready     chan struct{}
	pending   bool
	admitted  bool
	err       error
}

func NewWorkloadStreamLimiter(c WorkloadAPIStreamLimitsConfig, metrics telemetry.Metrics) *WorkloadStreamLimiter {
	l := &WorkloadStreamLimiter{
		limits:    c.clone(),
		active:    make(map[string]map[string]int),
		workloads: make(map[string]int),
		metrics:   metrics,
		groups:    make(map[string]map[selector.Selector]struct{}),
	}
	l.rebuildPoolsLocked()
	return l
}

func (l *WorkloadStreamLimiter) update(c WorkloadAPIStreamLimitsConfig) error {
	c = c.clone()
	if err := c.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limits = c
	l.rebuildPoolsLocked()
	l.admitWaitingLocked()
	// Give existing waiters available capacity before applying a smaller queue.
	for len(l.pending) > c.MaxPending {
		w := l.removeWaiterLocked(len(l.pending) - 1)
		w.err = l.reject(w.method)
		close(w.ready)
	}
	return nil
}

func (l *WorkloadStreamLimiter) validate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limits.Validate()
}

func (l *WorkloadStreamLimiter) stats() WorkloadAPIStreamStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	counts := make(map[string]int, len(l.pools))
	for _, pool := range l.pools {
		counts[pool.config.Name] = pool.active
	}
	return WorkloadAPIStreamStats{Active: l.total, Pending: len(l.pending), PoolActive: counts}
}

func (c WorkloadAPIStreamLimitsConfig) methodLimit(method string) int {
	switch method {
	case workload.MethodFetchX509SVID:
		return c.FetchX509SVID
	case workload.MethodFetchX509Bundles:
		return c.FetchX509Bundles
	case workload.MethodFetchJWTBundles:
		return c.FetchJWTBundles
	case sdsv3.MethodStreamSecrets:
		return c.StreamSecrets
	default:
		return 0
	}
}

// Acquire reserves every applicable allowance, waiting when policy permits.
func (l *WorkloadStreamLimiter) Acquire(ctx context.Context, method string, selectors []*common.Selector) (func(), error) {
	key, selectorSet := streamSelectorSnapshot(selectors)
	l.mu.Lock()
	if err := ctx.Err(); err != nil {
		l.mu.Unlock()
		return nil, status.FromContextError(err).Err()
	}
	l.admitWaitingLocked()
	if l.availableLocked(method, key, selectorSet) {
		l.reserveLocked(method, key, selectorSet)
		l.mu.Unlock()
		return l.releaseFunc(method, key), nil
	}
	if l.limits.MaxPending == 0 || len(l.pending) >= l.limits.MaxPending {
		l.mu.Unlock()
		return nil, l.reject(method)
	}
	w := &streamWaiter{ctx: ctx, method: method, key: key, selectors: selectorSet, ready: make(chan struct{}), pending: true}
	l.pending = append(l.pending, w)
	l.mu.Unlock()
	select {
	case <-w.ready:
	case <-ctx.Done():
	}
	l.mu.Lock()
	if w.pending {
		for i, pending := range l.pending {
			if pending == w {
				l.removeWaiterLocked(i)
				break
			}
		}
		w.err = status.FromContextError(ctx.Err()).Err()
		close(w.ready)
	}
	// Cancellation can win after another caller reserved capacity for this waiter.
	if w.admitted && ctx.Err() != nil {
		l.releaseLocked(method, key)
		w.admitted = false
		w.err = status.FromContextError(ctx.Err()).Err()
	}
	l.admitWaitingLocked()
	err := w.err
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return l.releaseFunc(method, key), nil
}

func (l *WorkloadStreamLimiter) availableLocked(method, key string, selectorSet map[selector.Selector]struct{}) bool {
	limit := l.limits.methodLimit(method)
	if (limit > 0 && l.active[method][key] >= limit) ||
		(l.limits.PerWorkload > 0 && l.workloads[key] >= l.limits.PerWorkload) ||
		(l.limits.Global > 0 && l.total >= l.limits.Global) {
		return false
	}
	for _, pool := range l.pools {
		if pool.config.Limit > 0 && pool.active >= pool.config.Limit && pool.matches(selectorSet) {
			return false
		}
	}
	return true
}

func (l *WorkloadStreamLimiter) reserveLocked(method, key string, selectorSet map[selector.Selector]struct{}) {
	l.groups[key] = selectorSet
	for i := range l.pools {
		if l.pools[i].matches(selectorSet) {
			l.pools[i].active++
		}
	}
	if l.active[method] == nil {
		l.active[method] = make(map[string]int)
	}
	l.active[method][key]++
	l.workloads[key]++
	l.total++
}

func (l *WorkloadStreamLimiter) releaseLocked(method, key string) {
	for i := range l.pools {
		if l.pools[i].matches(l.groups[key]) {
			l.pools[i].active--
		}
	}
	counts := l.active[method]
	counts[key]--
	if counts[key] == 0 {
		delete(counts, key)
	}
	if len(counts) == 0 {
		delete(l.active, method)
	}
	l.workloads[key]--
	if l.workloads[key] == 0 {
		delete(l.workloads, key)
		delete(l.groups, key)
	}
	l.total--
}

func (l *WorkloadStreamLimiter) releaseFunc(method, key string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.releaseLocked(method, key)
			l.admitWaitingLocked()
		})
	}
}

func (l *WorkloadStreamLimiter) removeWaiterLocked(i int) *streamWaiter {
	w := l.pending[i]
	last := len(l.pending) - 1
	copy(l.pending[i:], l.pending[i+1:])
	l.pending[last] = nil
	l.pending = l.pending[:last]
	w.pending = false
	return w
}

func (l *WorkloadStreamLimiter) admitWaitingLocked() {
	for i := 0; i < len(l.pending); {
		w := l.pending[i]
		if err := w.ctx.Err(); err != nil {
			w.err = status.FromContextError(err).Err()
		} else if l.availableLocked(w.method, w.key, w.selectors) {
			l.reserveLocked(w.method, w.key, w.selectors)
			w.admitted = true
		} else {
			i++
			continue
		}
		l.removeWaiterLocked(i)
		close(w.ready)
	}
}

func (l *WorkloadStreamLimiter) reject(method string) error {
	if l.metrics != nil {
		workloadapi.IncrStreamLimitExceededCounter(l.metrics, method)
	}
	return status.Errorf(codes.ResourceExhausted, "active stream admission capacity exhausted for %s", method)
}

// rebuildPoolsLocked reclassifies live streams before evaluating the pending queue.
func (l *WorkloadStreamLimiter) rebuildPoolsLocked() {
	l.pools = make([]streamPool, len(l.limits.Pools))
	for i, config := range l.limits.Pools {
		pool := &l.pools[i]
		pool.config = config
		for _, raw := range config.Selectors {
			kind, value, _ := strings.Cut(raw, ":")
			pool.selectors = append(pool.selectors, selector.Selector{Type: kind, Value: value})
		}
		for key, count := range l.workloads {
			if pool.matches(l.groups[key]) {
				pool.active += count
			}
		}
	}
}

// streamSelectorSnapshot retains immutable selector values for later policy updates.
func streamSelectorSnapshot(raw []*common.Selector) (string, map[selector.Selector]struct{}) {
	set := make(map[selector.Selector]struct{}, len(raw))
	for _, s := range raw {
		set[selector.Selector{Type: s.Type, Value: s.Value}] = struct{}{}
	}
	ordered := make([]selector.Selector, 0, len(set))
	for s := range set {
		ordered = append(ordered, s)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Type != ordered[j].Type {
			return ordered[i].Type < ordered[j].Type
		}
		return ordered[i].Value < ordered[j].Value
	})
	var key strings.Builder
	for _, s := range ordered {
		fmt.Fprintf(&key, "%d:%s%d:%s", len(s.Type), s.Type, len(s.Value), s.Value)
	}
	return key.String(), set
}
