package entrycache

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Hydrator struct {
	c *HydratorConfig
}

// Run starts a ticker which hydrates the in-memory entry cache.
func (h *Hydrator) Run(ctx context.Context) error {
	// Hydrate cache ASAP to unblock consumers of the cache
	h.hydrateEntryCacheFirstTime(ctx)

	t := h.c.Clock.Ticker(h.c.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			h.c.Log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-t.C:
			start := time.Now()
			err := h.hydrateEntryCache(ctx)
			end := time.Now()
			hydrateLog := h.c.Log.WithField(telemetry.ElapsedTime, end.Sub(start))
			if err != nil {
				hydrateLog.WithError(err).Error("Failed to reload entry cache")
			} else {
				hydrateLog.Debug("Reloaded entry cache")
			}
		}
	}
}

func (h *Hydrator) hydrateEntryCacheFirstTime(ctx context.Context) {
	var err error
	err = h.hydrateEntryCache(ctx)
	// Retry indefinitely until the cache can be hydrated the first time
	for err != nil {
		h.c.Log.WithError(err).Error("Could not hydrate in-memory entry cache first time, retrying")
		err = h.hydrateEntryCache(ctx)
	}
}

func (h *Hydrator) hydrateEntryCache(ctx context.Context) (err error) {
	call := telemetry.StartCall(h.c.Metrics, telemetry.Entry, telemetry.Cache, telemetry.Reload)
	defer call.Done(&err)
	err = h.c.EntryCache.Hydrate(ctx)
	return err
}
