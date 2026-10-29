package cache

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
)

// BundleCacheConfig configures the manager's shared bundle view.
//
// MaxStaleness controls how long a federated bundle remains visible after it
// was last confirmed by a complete, successful server response. A non-positive
// value disables freshness enforcement. The agent's own trust-domain bundle is
// never subject to the limit.
type BundleCacheConfig struct {
	TrustDomain  spiffeid.TrustDomain
	Bundle       *Bundle
	MaxStaleness time.Duration
	Clock        clock.Clock
	Metrics      telemetry.Metrics
	Log          logrus.FieldLogger
}

// Run enforces configured federated-bundle deadlines until the context is
// cancelled. Run is intentionally separate from construction so callers can
// fully wire consumers before expiry notifications are possible.
//
// Run is safe to execute when freshness enforcement is disabled. In that case
// it waits for cancellation without creating timers.
func (c *BundleCache) Run(ctx context.Context) error {
	if c.maxStaleness <= 0 {
		<-ctx.Done()
		return nil
	}

	for {
		deadline, ok := c.nextDeadline()
		if !ok {
			select {
			case <-ctx.Done():
				return nil
			case <-c.wake:
				continue
			}
		}

		wait := deadline.Sub(c.clk.Now())
		if wait <= 0 {
			c.expireDue(c.clk.Now())
			continue
		}

		timer := c.clk.Timer(wait)
		// Recheck the absolute deadline because the clock can advance while the
		// timer is being installed; otherwise expiry could be delayed by another
		// full staleness period.
		if now := c.clk.Now(); !now.Before(deadline) {
			timer.Stop()
			c.expireDue(now)
			continue
		}

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-c.wake:
			// A confirmation, removal, or re-admission may have changed the
			// earliest deadline. Recompute instead of trusting this timer.
			timer.Stop()
			continue
		case <-timer.C:
			c.expireDue(c.clk.Now())
		}
	}
}

// confirm atomically replaces the server-confirmed source set and refreshes
// the deadline of every federated bundle present in that set.
func (c *BundleCache) confirm(bundles map[spiffeid.TrustDomain]*Bundle, now time.Time) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()

	c.mu.Lock()
	currentVisible := c.visibleLocked()
	previousSource := c.source
	nextSource := copyBundleMap(bundles)
	if nextSource == nil {
		nextSource = make(map[spiffeid.TrustDomain]*Bundle)
	}

	// The own trust-domain bundle authenticates the server and is outside the
	// federated freshness policy. Preserve it when an invalid server response
	// omits it, matching the cache's historical safety behavior.
	if _, ok := nextSource[c.trustDomain]; !ok {
		if own := c.source[c.trustDomain]; own != nil {
			nextSource[c.trustDomain] = own
		} else if own := currentVisible[c.trustDomain]; own != nil {
			nextSource[c.trustDomain] = own
		}
	}

	nextConfirmed := make(map[spiffeid.TrustDomain]time.Time, len(nextSource))
	nextStale := make(map[spiffeid.TrustDomain]struct{})
	readmitted := 0
	removed := 0
	for td := range previousSource {
		if td == c.trustDomain {
			continue
		}
		if _, ok := nextSource[td]; !ok {
			removed++
		}
	}
	for td := range nextSource {
		if td == c.trustDomain {
			continue
		}
		nextConfirmed[td] = now
		if _, wasStale := c.stale[td]; wasStale {
			readmitted++
		}
	}

	c.source = nextSource
	c.confirmedAt = nextConfirmed
	c.stale = nextStale
	nextVisible := c.visibleLocked()
	changed := !bundleMapsEqual(currentVisible, nextVisible)
	fresh, stale := c.countsLocked()
	c.mu.Unlock()

	c.emitStateMetrics(fresh, stale)
	if readmitted > 0 {
		telemetry_agent.IncrementFederatedBundleReadmissions(c.metrics, readmitted)
	}
	if c.log != nil && c.maxStaleness > 0 && (readmitted > 0 || removed > 0) {
		c.log.WithFields(logrus.Fields{
			"fresh_bundles":      fresh,
			"stale_bundles":      stale,
			"readmitted_bundles": readmitted,
			"removed_bundles":    removed,
			"max_staleness":      c.maxStaleness,
		}).Info("Federated bundle freshness state changed after server confirmation")
	}
	if changed {
		c.publish(nextVisible)
	}
	c.signalWake()
}

// UpdateUnconfirmed applies fetched changes to previously accepted bundles
// without refreshing their confirmation times. New federated bundles wait for
// a complete synchronization before entering the visible source.
func (c *BundleCache) UpdateUnconfirmed(bundles map[spiffeid.TrustDomain]*Bundle) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()

	c.mu.Lock()
	currentVisible := c.visibleLocked()
	previousSource := copyBundleMap(c.source)
	for td := range c.source {
		if td == c.trustDomain {
			if own, present := bundles[td]; present {
				c.source[td] = own
			}
			continue
		}
		if bundle, present := bundles[td]; present {
			c.source[td] = bundle
			continue
		}
		delete(c.source, td)
		delete(c.confirmedAt, td)
		delete(c.stale, td)
	}
	if bundleMapsEqual(previousSource, c.source) {
		c.mu.Unlock()
		return
	}
	nextVisible := c.visibleLocked()
	fresh, stale := c.countsLocked()
	c.mu.Unlock()

	c.emitStateMetrics(fresh, stale)
	if !bundleMapsEqual(currentVisible, nextVisible) {
		c.publish(nextVisible)
	}
	c.signalWake()
}

// expireDue marks every bundle at or past its current deadline stale. The
// current confirmation map is checked while holding the transition lock, so a
// timer created for an older confirmation cannot expire a newly confirmed
// bundle.
func (c *BundleCache) expireDue(now time.Time) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()

	c.mu.Lock()
	expired := 0
	for td, confirmedAt := range c.confirmedAt {
		if td == c.trustDomain {
			continue
		}
		if _, alreadyStale := c.stale[td]; alreadyStale {
			continue
		}
		deadline := confirmedAt.Add(c.maxStaleness)
		if now.Before(deadline) {
			continue
		}
		c.stale[td] = struct{}{}
		expired++
	}

	if expired == 0 {
		c.mu.Unlock()
		return
	}

	nextVisible := c.visibleLocked()
	fresh, stale := c.countsLocked()
	c.mu.Unlock()

	c.emitStateMetrics(fresh, stale)
	telemetry_agent.IncrementFederatedBundleExpirations(c.metrics, expired)
	if c.log != nil {
		c.log.WithFields(logrus.Fields{
			"expired_bundles": expired,
			"fresh_bundles":   fresh,
			"stale_bundles":   stale,
			"max_staleness":   c.maxStaleness,
		}).Warn("Federated bundles exceeded the configured maximum staleness")
	}
	c.publish(nextVisible)
}

func (c *BundleCache) nextDeadline() (time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var earliest time.Time
	for td, confirmedAt := range c.confirmedAt {
		if td == c.trustDomain {
			continue
		}
		if _, isStale := c.stale[td]; isStale {
			continue
		}
		deadline := confirmedAt.Add(c.maxStaleness)
		if earliest.IsZero() || deadline.Before(earliest) {
			earliest = deadline
		}
	}
	return earliest, !earliest.IsZero()
}

// c.mu must be held for reading or writing. The returned map is detached from
// the freshness bookkeeping before publication.
func (c *BundleCache) visibleLocked() map[spiffeid.TrustDomain]*Bundle {
	visible := make(map[spiffeid.TrustDomain]*Bundle, len(c.source))
	for td, bundle := range c.source {
		if td != c.trustDomain {
			if _, isStale := c.stale[td]; isStale {
				continue
			}
		}
		visible[td] = bundle
	}
	return visible
}

func (c *BundleCache) countsLocked() (fresh, stale int) {
	for td := range c.source {
		if td == c.trustDomain {
			continue
		}
		if _, isStale := c.stale[td]; isStale {
			stale++
		} else {
			fresh++
		}
	}
	return fresh, stale
}

func (c *BundleCache) publish(bundles map[spiffeid.TrustDomain]*Bundle) {
	c.bundles.Update(copyBundleMap(bundles))
}

func (c *BundleCache) signalWake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *BundleCache) emitStateMetrics(fresh, stale int) {
	telemetry_agent.SetFederatedBundleFreshnessCounts(c.metrics, fresh, stale)
}
