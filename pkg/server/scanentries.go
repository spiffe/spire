package server

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	serverTelemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
)

var (
	// entryScanPageSize defaults to 200 but can be mutated by unit tests to
	// easier test page handling
	entryScanPageSize int32 = 200
)

// scanForBadEntries scans the entry list for entries that we will ignore
// because they contain problematic spiffe IDs. It will never return an
// error since it is advisory only.
func scanForBadEntries(log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		pagination := &datastore.Pagination{PageSize: entryScanPageSize}
		ignored := 0
		for {
			resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				Pagination: pagination,
			})
			if err != nil {
				log.WithError(err).Warn("Failed to scan for bad entries")
				return nil
			}

			for _, entry := range resp.Entries {
				if err := idutil.CheckIDStringNormalization(entry.ParentId); err != nil {
					log.WithFields(logrus.Fields{
						telemetry.ParentID:       entry.ParentId,
						telemetry.SPIFFEID:       entry.SpiffeId,
						telemetry.RegistrationID: entry.EntryId,
						logrus.ErrorKey:          err,
					}).Error("Ignoring entry with invalid parentID; this entry will be automatically deleted by a future release")
					ignored++
					continue
				}
				if err := idutil.CheckIDStringNormalization(entry.SpiffeId); err != nil {
					log.WithFields(logrus.Fields{
						telemetry.ParentID:       entry.ParentId,
						telemetry.SPIFFEID:       entry.SpiffeId,
						telemetry.RegistrationID: entry.EntryId,
						logrus.ErrorKey:          err,
					}).Error("Ignoring entry with invalid spiffeID; this entry will be automatically deleted by a future release")
					ignored++
					continue
				}
			}

			switch {
			case resp.Pagination == nil, resp.Pagination.Token == "":
				serverTelemetry.SetEntryIgnoredGauge(metrics, ignored)
				return nil
			}
			pagination.Token = resp.Pagination.Token
		}
	}
}
