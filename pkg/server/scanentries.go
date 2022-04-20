package server

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	serverTelemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/datastore"
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
		deleted := 0
		for {
			resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				Pagination: pagination,
			})
			if err != nil {
				log.WithError(err).Warn("Failed to scan for bad entries")
				return nil
			}

			for _, entry := range resp.Entries {
				if _, err := spiffeid.FromString(entry.ParentId); err != nil {
					log.WithFields(logrus.Fields{
						telemetry.ParentID:       entry.ParentId,
						telemetry.SPIFFEID:       entry.SpiffeId,
						telemetry.RegistrationID: entry.EntryId,
						logrus.ErrorKey:          err,
					}).Error("Deleting entry with invalid parentID")
					deleted++
					if _, err := ds.DeleteRegistrationEntry(ctx, entry.EntryId); err != nil {
						log.WithError(err).Error("Failed to delete entry with an invalid parentID")
					}
					continue
				}
				if _, err := spiffeid.FromString(entry.SpiffeId); err != nil {
					log.WithFields(logrus.Fields{
						telemetry.ParentID:       entry.ParentId,
						telemetry.SPIFFEID:       entry.SpiffeId,
						telemetry.RegistrationID: entry.EntryId,
						logrus.ErrorKey:          err,
					}).Error("Deleting entry with invalid spiffeID")
					deleted++
					if _, err := ds.DeleteRegistrationEntry(ctx, entry.EntryId); err != nil {
						log.WithError(err).Error("Failed to delete entry with an invalid spiffeID")
					}
					continue
				}
			}

			switch {
			case resp.Pagination == nil, resp.Pagination.Token == "":
				serverTelemetry.SetEntryDeletedGauge(metrics, deleted)
				return nil
			}
			pagination.Token = resp.Pagination.Token
		}
	}
}
