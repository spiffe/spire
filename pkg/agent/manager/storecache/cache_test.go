package storecache_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td              = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTD     = spiffeid.RequireTrustDomainFromString("federated.td1")
	tdBundle        = spiffebundle.FromX509Authorities(td, []*x509.Certificate{{Raw: []byte{1}}})
	federatedBundle = spiffebundle.FromX509Authorities(federatedTD, []*x509.Certificate{{Raw: []byte{2}}})
	fohID           = spiffeid.RequireFromPath(td, "/foh")
	barID           = spiffeid.RequireFromPath(td, "/bar")
	bazID           = spiffeid.RequireFromPath(td, "/baz")
)

func TestUpdateEntriesWithMultipleEntries(t *testing.T) {
	log, _ := test.NewNullLogger()

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	update := &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       fohID.String(),
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			"bar": {
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       barID.String(),
				StoreSvid:      true,
				FederatesWith:  []string{federatedTD.IDString()},
				RevisionNumber: 1,
			},
		},
	}

	c.UpdateEntries(update, nil)

	expectedRecords := []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}

	require.Equal(t, expectedRecords, c.Records())

	// Update entry foh and keep bar
	update = &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
				},
				SpiffeId:  fohID.String(),
				StoreSvid: true,
				// Set a new entry revision number
				RevisionNumber: 3,
			},
			"bar": {
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       barID.String(),
				StoreSvid:      true,
				FederatesWith:  []string{federatedTD.IDString()},
				RevisionNumber: 1,
			},
		},
	}

	// Call update entries again to update cache
	c.UpdateEntries(update, nil)

	expectedRecords = []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 3,
			},
			// Record revision changed
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}
	require.Equal(t, expectedRecords, c.Records())
}

func TestUpdateEntries(t *testing.T) {
	// Create new versions for trust domain and federated bundles
	tdBundleUpdated := spiffebundle.FromX509Authorities(td, []*x509.Certificate{{Raw: []byte{8}}})
	federatedBundleUpdated := spiffebundle.FromX509Authorities(federatedTD, []*x509.Certificate{{Raw: []byte{9}}})

	for _, tt := range []struct {
		name string
		// Initial update used to create test case environment
		initialUpdate *cache.UpdateEntries
		// Update a provided UpdateEntries
		setUpdate func(update cache.UpdateEntries) *cache.UpdateEntries
		checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *cache.X509SVID) bool
		logs      []spiretest.LogEntry
		// Expected records on cache
		expectedRecords []*storecache.Record
		// Expected list of stale entries
		expectedStaleEntries []*cache.StaleEntry
	}{
		{
			name: "federated bundle Removed",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				delete(update.Bundles, federatedTD)
				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: tdBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						FederatesWith:  []string{"federated.td1"},
						SpiffeId:       fohID.String(),
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					Revision: 2,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level: logrus.DebugLevel,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "federated.td1",
					},
					Message: "Bundle removed",
				},
			},
		},
		{
			name: "federated bundle updated",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				update.Bundles[federatedTD] = federatedBundleUpdated
				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundle,
						federatedTD: federatedBundleUpdated,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						SpiffeId:       fohID.String(),
						FederatesWith:  []string{"federated.td1"},
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					Revision: 2,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level: logrus.DebugLevel,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "federated.td1",
					},
					Message: "Bundle updated",
				},
			},
		},
		{
			name: "trust domain bundle updated",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				update.Bundles[td] = tdBundleUpdated
				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundleUpdated,
						federatedTD: federatedBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						FederatesWith:  []string{"federated.td1"},
						SpiffeId:       fohID.String(),
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					Revision: 2,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level: logrus.DebugLevel,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "example.org",
					},
					Message: "Bundle updated",
				},
			},
		},
		{
			name: "entry updated",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				updatedEntry := createTestEntry()
				updatedEntry.RevisionNumber = 3
				updatedEntry.X509SvidTtl = 2345
				updatedEntry.JwtSvidTtl = 3456

				update.RegistrationEntries["foh"] = updatedEntry

				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundle,
						federatedTD: federatedBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						FederatesWith:  []string{"federated.td1"},
						SpiffeId:       fohID.String(),
						StoreSvid:      true,
						RevisionNumber: 3,
						X509SvidTtl:    2345,
						JwtSvidTtl:     3456,
					},
					Revision: 2,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level: logrus.DebugLevel,
					Data: logrus.Fields{
						telemetry.Entry:    "foh",
						telemetry.SPIFFEID: "spiffe://example.org/foh",
					},
					Message: "Entry updated",
				},
			},
		},
		{
			name: "update svid",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			checkSVID: func(re1, re2 *common.RegistrationEntry, xs *cache.X509SVID) bool {
				return true
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundle,
						federatedTD: federatedBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						FederatesWith:  []string{"federated.td1"},
						SpiffeId:       fohID.String(),
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					// Revision was not updated but Stale entry created
					Revision: 1,
				},
			},
			expectedStaleEntries: []*cache.StaleEntry{
				{
					// New SVID, ExpiresAt not expected
					Entry: createTestEntry(),
				},
			},
		},
		{
			name: "entry created",
			initialUpdate: &cache.UpdateEntries{
				Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					td:          tdBundle,
					federatedTD: federatedBundle,
				},
				RegistrationEntries: map[string]*common.RegistrationEntry{
					"foh": createTestEntry(),
				},
			},
			setUpdate: func(update cache.UpdateEntries) *cache.UpdateEntries {
				// Add new entry to update entries
				newEntry := &common.RegistrationEntry{
					EntryId:  "bar",
					ParentId: td.IDString(),
					SpiffeId: barID.String(),
					Selectors: []*common.Selector{
						{Type: "c", Value: "c:3"},
					},
					StoreSvid:      true,
					RevisionNumber: 1,
				}

				update.RegistrationEntries["bar"] = newEntry
				return &update
			},
			expectedRecords: []*storecache.Record{
				{
					ID: "bar",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundle,
						federatedTD: federatedBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "bar",
						Selectors: []*common.Selector{
							{Type: "c", Value: "c:3"},
						},
						ParentId:       "spiffe://example.org",
						SpiffeId:       "spiffe://example.org/bar",
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					Revision: 1,
				},
				{
					ID: "foh",
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td:          tdBundle,
						federatedTD: federatedBundle,
					},
					Entry: &common.RegistrationEntry{
						EntryId: "foh",
						Selectors: []*common.Selector{
							{Type: "a", Value: "b:1"},
							{Type: "a", Value: "c:2"},
						},
						FederatesWith:  []string{"federated.td1"},
						SpiffeId:       fohID.String(),
						StoreSvid:      true,
						RevisionNumber: 1,
					},
					Revision: 1,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level: logrus.DebugLevel,
					Data: logrus.Fields{
						telemetry.Entry:    "bar",
						telemetry.SPIFFEID: "spiffe://example.org/bar",
					},
					Message: "Entry created",
				},
			},
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			log.Level = logrus.DebugLevel

			c := storecache.New(&storecache.Config{
				Log:         log,
				TrustDomain: td,
			})

			c.UpdateEntries(tt.initialUpdate, nil)
			update := tt.setUpdate(*tt.initialUpdate)
			// Dont care about initialization logs
			hook.Reset()

			// Set check SVID only in updates, creation will is tested in a different test
			c.UpdateEntries(update, tt.checkSVID)

			spiretest.AssertLogs(t, hook.AllEntries(), tt.logs)
			require.Equal(t, tt.expectedRecords, c.Records())
			require.Equal(t, tt.expectedStaleEntries, c.GetStaleEntries())
		})
	}
}

func TestUpdateEntriesRemoveEntry(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	update := &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       fohID.String(),
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			"bar": {
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       barID.String(),
				StoreSvid:      true,
				FederatesWith:  []string{federatedTD.IDString()},
				RevisionNumber: 1,
			},
		},
	}

	c.UpdateEntries(update, nil)
	expectedRecords := []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}

	require.Equal(t, expectedRecords, c.Records())

	// Remove 'bar'
	update = &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       fohID.String(),
				StoreSvid:      true,
				RevisionNumber: 1,
			},
		},
	}

	// Reset logs, this test dont cares about creating logs
	hook.Reset()
	// Update entry to remove 'bar'
	c.UpdateEntries(update, nil)

	// Expects that 'bar' is mark as delete, setting entry = nil and
	// handledEntry contains actual entry.
	expectedRecords = []*storecache.Record{
		{
			ID: "bar",
			HandledEntry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}

	require.Equal(t, expectedRecords, c.Records())

	// Update SVIDs does not updates records that are in remove state
	c.UpdateSVIDs(&cache.UpdateSVIDs{
		X509SVIDs: map[string]*cache.X509SVID{
			"bar": {
				Chain: []*x509.Certificate{
					{Raw: []byte{1}},
				},
			},
			"foh": {
				Chain: []*x509.Certificate{
					{Raw: []byte{2}},
				},
			},
		},
	})
	expectedRecords = []*storecache.Record{
		{
			ID: "bar",
			HandledEntry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
			Svid: &cache.X509SVID{
				Chain: []*x509.Certificate{
					{Raw: []byte{2}},
				},
			},
		},
	}
	require.Equal(t, expectedRecords, c.Records())

	// Update handle revision, and verify that after update, record is removed
	c.HandledRecord(&common.RegistrationEntry{
		EntryId: "bar",
		Selectors: []*common.Selector{
			{Type: "d", Value: "b:1"},
		},
		SpiffeId:       "spiffe://example.org/bar",
		FederatesWith:  []string{"spiffe://federated.td1"},
		StoreSvid:      true,
		RevisionNumber: 1,
	}, 2)

	c.UpdateEntries(update, nil)
	expectedRecords = []*storecache.Record{
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
			Svid: &cache.X509SVID{
				Chain: []*x509.Certificate{
					{Raw: []byte{2}},
				},
			},
		},
	}
	require.Equal(t, expectedRecords, c.Records())
}

func TestUpdateEntriesCreatesNewEntriesOnCache(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	update := &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       fohID.String(),
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			"bar": {
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       barID.String(),
				StoreSvid:      true,
				FederatesWith:  []string{federatedTD.IDString()},
				RevisionNumber: 1,
			},
		},
	}

	c.UpdateEntries(update, nil)
	expectedRecords := []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}

	require.Equal(t, expectedRecords, c.Records())

	expectedLogs := []spiretest.LogEntry{
		{
			Level:   logrus.DebugLevel,
			Message: "Bundle added",
			Data: logrus.Fields{
				"trust_domain_id": "federated.td1",
			},
		},
		{
			Level:   logrus.DebugLevel,
			Message: "Bundle added",
			Data: logrus.Fields{
				"trust_domain_id": "example.org",
			},
		},
		{
			Level:   logrus.DebugLevel,
			Message: "Entry created",
			Data: logrus.Fields{
				"entry":     "foh",
				"spiffe_id": "spiffe://example.org/foh",
			},
		},
		{
			Level:   logrus.DebugLevel,
			Message: "Entry created",
			Data: logrus.Fields{
				"entry":     "bar",
				"spiffe_id": "spiffe://example.org/bar",
			},
		},
	}
	spiretest.AssertLogsAnyOrder(t, hook.AllEntries(), expectedLogs)
}

func TestTaintX509SVIDs(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	fakeMetrics := fakemetrics.New()
	taintedAuthority := testca.New(t, td)
	newAuthority := testca.New(t, td)

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
		Metrics:     fakeMetrics,
	})

	// Create initial entries
	entries := makeEntries(td, "e1", "e2", "e3", "e4", "e5")
	updateEntries := &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td: tdBundle,
		},
		RegistrationEntries: entries,
	}

	// Set entries to cache
	c.UpdateEntries(updateEntries, nil)

	noTaintedSVID := createX509SVID(td, "e3", newAuthority)
	updateSVIDs := &cache.UpdateSVIDs{
		X509SVIDs: map[string]*cache.X509SVID{
			"e1": createX509SVID(td, "e1", taintedAuthority),
			"e2": createX509SVID(td, "e2", taintedAuthority),
			"e3": noTaintedSVID,
			"e5": createX509SVID(td, "e5", taintedAuthority),
		},
	}
	c.UpdateSVIDs(updateSVIDs)

	for _, tt := range []struct {
		name               string
		taintedAuthorities []*x509.Certificate
		expectSVID         map[string]*cache.X509SVID
		expectLogs         []spiretest.LogEntry
		expectMetrics      []fakemetrics.MetricItem
	}{
		{
			name:               "taint SVIDs",
			taintedAuthorities: taintedAuthority.X509Authorities(),
			expectSVID: map[string]*cache.X509SVID{
				"e1": nil,
				"e2": nil,
				"e3": noTaintedSVID,
				"e4": nil,
				"e5": nil,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Tainted X.509 SVIDs",
					Data: logrus.Fields{
						telemetry.TaintedX509SVIDs: "3",
					},
				},
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.ExpiringSVIDs, agent.CacheTypeSVIDStore},
					Val:  3,
				},
				{
					Type:   fakemetrics.IncrCounterWithLabelsType,
					Key:    []string{telemetry.CacheManager, agent.CacheTypeSVIDStore, telemetry.ProcessTaintedX509SVIDs},
					Val:    1,
					Labels: []metrics.Label{{Name: "status", Value: "OK"}},
				},
				{
					Type:   fakemetrics.MeasureSinceWithLabelsType,
					Key:    []string{telemetry.CacheManager, agent.CacheTypeSVIDStore, telemetry.ProcessTaintedX509SVIDs, telemetry.ElapsedTime},
					Val:    0,
					Labels: []metrics.Label{{Name: "status", Value: "OK"}},
				},
			},
		},
		{
			name:               "taint again",
			taintedAuthorities: taintedAuthority.X509Authorities(),
			expectSVID: map[string]*cache.X509SVID{
				"e1": nil,
				"e2": nil,
				"e3": noTaintedSVID,
				"e4": nil,
				"e5": nil,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Tainted X.509 SVIDs",
					Data: logrus.Fields{
						telemetry.TaintedX509SVIDs: "0",
					},
				},
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.ExpiringSVIDs, agent.CacheTypeSVIDStore},
					Val:  0,
				},
				{
					Type:   fakemetrics.IncrCounterWithLabelsType,
					Key:    []string{telemetry.CacheManager, agent.CacheTypeSVIDStore, telemetry.ProcessTaintedX509SVIDs},
					Val:    1,
					Labels: []metrics.Label{{Name: "status", Value: "OK"}},
				},
				{
					Type:   fakemetrics.MeasureSinceWithLabelsType,
					Key:    []string{telemetry.CacheManager, agent.CacheTypeSVIDStore, telemetry.ProcessTaintedX509SVIDs, telemetry.ElapsedTime},
					Val:    0,
					Labels: []metrics.Label{{Name: "status", Value: "OK"}},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hook.Reset()
			fakeMetrics.Reset()

			c.TaintX509SVIDs(ctx, tt.taintedAuthorities)
			assert.Equal(t, tt.expectSVID, svidMapFromRecords(c.Records()))
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
			assert.Equal(t, tt.expectMetrics, fakeMetrics.AllMetrics())
		})
	}
}

func TestUpdateSVIDs(t *testing.T) {
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	key := spiretest.DefaultKey

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	update := createUpdateEntries()
	c.UpdateEntries(update, nil)
	hook.Reset()

	updateSVIDs := &cache.UpdateSVIDs{
		X509SVIDs: map[string]*cache.X509SVID{
			"baz": {
				Chain:      []*x509.Certificate{{URIs: []*url.URL{bazID.URL()}}},
				PrivateKey: key,
			},
			"foh": {
				Chain:      []*x509.Certificate{{URIs: []*url.URL{fohID.URL()}}},
				PrivateKey: key,
			},
		},
	}

	// Run update SVIDs to set new SVIDs on cache
	c.UpdateSVIDs(updateSVIDs)

	expectedRecords := []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 2,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
			Svid: &cache.X509SVID{
				Chain:      []*x509.Certificate{{URIs: []*url.URL{fohID.URL()}}},
				PrivateKey: key,
			},
		},
	}
	require.Equal(t, expectedRecords, c.Records())

	expectedLogs := []spiretest.LogEntry{
		{
			Level:   logrus.ErrorLevel,
			Message: "Entry not found",
			Data:    logrus.Fields{"entry_id": "baz"},
		},
		{
			Level:   logrus.DebugLevel,
			Message: "SVID updated",
			Data:    logrus.Fields{"entry": "foh", "spiffe_id": "spiffe://example.org/foh"},
		},
	}
	spiretest.AssertLogsAnyOrder(t, hook.AllEntries(), expectedLogs)
}

func TestGetStaleEntries(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	update := createUpdateEntries()
	fohEntry := update.RegistrationEntries["foh"]
	barEntry := update.RegistrationEntries["bar"]

	c.UpdateEntries(update, func(re1, re2 *common.RegistrationEntry, xs *cache.X509SVID) bool {
		// Set only 'foh' as stale
		return re2.EntryId == "foh"
	})

	expectedStaleEntries := []*cache.StaleEntry{
		{
			Entry: fohEntry,
		},
	}
	require.Equal(t, expectedStaleEntries, c.GetStaleEntries())

	expiresAt := time.Now().Add(time.Minute)

	// Call UpdateSVID to remove 'foh' from stale entries
	c.UpdateSVIDs(&cache.UpdateSVIDs{
		X509SVIDs: map[string]*cache.X509SVID{
			"foh": {
				Chain: []*x509.Certificate{
					{
						URIs:     []*url.URL{fohID.URL()},
						NotAfter: expiresAt,
					},
				},
			},
		},
	})
	require.Empty(t, c.GetStaleEntries())

	// Call update but mark both records as stale.
	c.UpdateEntries(update, func(re1, re2 *common.RegistrationEntry, xs *cache.X509SVID) bool {
		return true
	})

	// Expects ordered list and 'ExpiresAt' is set on entries with SVID
	expectedStaleEntries = []*cache.StaleEntry{
		{
			Entry: barEntry,
		},
		{
			Entry:         fohEntry,
			SVIDExpiresAt: expiresAt,
		},
	}
	require.Equal(t, expectedStaleEntries, c.GetStaleEntries())
}

func TestCheckSVID(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	entry := createTestEntry()
	update := &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": entry,
		},
	}
	// All new entries so not expecting previous entry or svid.
	c.UpdateEntries(update, func(re1, re2 *common.RegistrationEntry, xs *cache.X509SVID) bool {
		assert.Nil(t, re1)
		assert.Equal(t, entry, re2)
		assert.Nil(t, xs)
		return true
	})

	x509SVID := &cache.X509SVID{
		Chain: []*x509.Certificate{{URIs: []*url.URL{fohID.URL()}}},
	}
	// Set an SVID to record
	c.UpdateSVIDs(&cache.UpdateSVIDs{
		X509SVIDs: map[string]*cache.X509SVID{
			"foh": x509SVID,
		},
	})

	// Creating new entry with same information instead of cloning and change revision
	updatedEntry := createTestEntry()
	updatedEntry.RevisionNumber = 10
	update = &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": updatedEntry,
		},
	}
	// Record already exists so previous entry is expected, and it has an SVID
	c.UpdateEntries(update, func(re1, re2 *common.RegistrationEntry, xs *cache.X509SVID) bool {
		assert.Equal(t, entry, re1)
		assert.Equal(t, updatedEntry, re2)
		assert.Equal(t, x509SVID, xs)
		return true
	})
}

func TestReadyToStore(t *testing.T) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := storecache.New(&storecache.Config{
		Log:         log,
		TrustDomain: td,
	})

	// No records to store
	require.Empty(t, c.ReadyToStore())

	update := createUpdateEntries()
	c.UpdateEntries(update, nil)

	expectedRecords := []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
		{
			ID: "foh",
			Entry: &common.RegistrationEntry{
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       "spiffe://example.org/foh",
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}

	// All new records are sent to ready to store list,
	require.Equal(t, expectedRecords, c.ReadyToStore())

	// Set handle version to current revision
	c.HandledRecord(update.RegistrationEntries["foh"], 1)

	expectedRecords = []*storecache.Record{
		{
			ID: "bar",
			Entry: &common.RegistrationEntry{
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       "spiffe://example.org/bar",
				FederatesWith:  []string{"spiffe://federated.td1"},
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			Revision: 1,
			Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				td:          tdBundle,
				federatedTD: federatedBundle,
			},
		},
	}
	require.Equal(t, expectedRecords, c.ReadyToStore())
}

func createUpdateEntries() *cache.UpdateEntries {
	return &cache.UpdateEntries{
		Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td:          tdBundle,
			federatedTD: federatedBundle,
		},
		RegistrationEntries: map[string]*common.RegistrationEntry{
			"foh": {
				EntryId: "foh",
				Selectors: []*common.Selector{
					{Type: "a", Value: "b:1"},
					{Type: "a", Value: "c:2"},
				},
				SpiffeId:       fohID.String(),
				StoreSvid:      true,
				RevisionNumber: 1,
			},
			"bar": {
				EntryId: "bar",
				Selectors: []*common.Selector{
					{Type: "d", Value: "b:1"},
				},
				SpiffeId:       barID.String(),
				StoreSvid:      true,
				FederatesWith:  []string{federatedTD.IDString()},
				RevisionNumber: 1,
			},
		},
	}
}

func createTestEntry() *common.RegistrationEntry {
	return &common.RegistrationEntry{
		EntryId: "foh",
		Selectors: []*common.Selector{
			{Type: "a", Value: "b:1"},
			{Type: "a", Value: "c:2"},
		},
		SpiffeId:       fohID.String(),
		FederatesWith:  []string{federatedTD.Name()},
		StoreSvid:      true,
		RevisionNumber: 1,
	}
}

func svidMapFromRecords(records []*storecache.Record) map[string]*cache.X509SVID {
	recordsMap := make(map[string]*cache.X509SVID, len(records))
	for _, eachRecord := range records {
		recordsMap[eachRecord.ID] = eachRecord.Svid
	}
	return recordsMap
}

func createX509SVID(td spiffeid.TrustDomain, id string, ca *testca.CA) *cache.X509SVID {
	chain, key := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(td, "/"+id)),
	)
	return &cache.X509SVID{
		Chain:      chain,
		PrivateKey: key,
	}
}

func makeEntries(td spiffeid.TrustDomain, ids ...string) map[string]*common.RegistrationEntry {
	entries := make(map[string]*common.RegistrationEntry, len(ids))
	for _, id := range ids {
		entries[id] = &common.RegistrationEntry{
			EntryId:   id,
			SpiffeId:  spiffeid.RequireFromPath(td, "/"+id).String(),
			Selectors: makeSelectors(id),
			StoreSvid: true,
		}
	}
	return entries
}

func makeSelectors(values ...string) []*common.Selector {
	var selectors []*common.Selector
	for _, value := range values {
		selectors = append(selectors, &common.Selector{
			Type:  "t",
			Value: fmt.Sprintf("v:%s", value),
		})
	}
	return selectors
}
