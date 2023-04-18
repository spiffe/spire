package store

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_store "github.com/spiffe/spire/pkg/common/telemetry/agent/store"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultInterval = 5 * time.Second
)

type Cache interface {
	// ReadyToStore is a list of store cache records that are ready to be stored on specific SVID Store
	ReadyToStore() []*storecache.Record
	// HandledRecord sets a revision to record on cache
	HandledRecord(entry *common.RegistrationEntry, revision int64)
}

type Config struct {
	Clk         clock.Clock
	Log         logrus.FieldLogger
	TrustDomain spiffeid.TrustDomain
	Cache       Cache
	Catalog     catalog.Catalog
	Metrics     telemetry.Metrics
}

type SVIDStoreService struct {
	clk clock.Clock
	log logrus.FieldLogger
	// trustDomain is the trust domain of the agent
	trustDomain spiffeid.TrustDomain
	// cache is the store cache
	cache   Cache
	cat     catalog.Catalog
	metrics telemetry.Metrics

	hooks struct {
		// test hook used to verify if a cycle finished
		storeFinished chan struct{}
	}
}

func New(c *Config) *SVIDStoreService {
	clk := c.Clk
	if clk == nil {
		clk = clock.New()
	}

	return &SVIDStoreService{
		cache:       c.Cache,
		clk:         clk,
		log:         c.Log,
		metrics:     c.Metrics,
		trustDomain: c.TrustDomain,
		cat:         c.Catalog,
	}
}

// SetStoreFinishedHook used for testing only
func (s *SVIDStoreService) SetStoreFinishedHook(storeFinished chan struct{}) {
	s.hooks.storeFinished = storeFinished
}

// Run starts SVID Store service
func (s *SVIDStoreService) Run(ctx context.Context) error {
	timer := s.clk.Timer(defaultInterval)
	defer timer.Stop()

	for {
		s.processRecords(ctx)
		timer.Reset(defaultInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// deleteSVID deletes a stored SVID that uses the SVIDStore plugin. It gets the plugin name from entry selectors
func (s *SVIDStoreService) deleteSVID(ctx context.Context, log logrus.FieldLogger, entry *common.RegistrationEntry) bool {
	log = log.WithFields(logrus.Fields{
		telemetry.Entry:    entry.EntryId,
		telemetry.SPIFFEID: entry.SpiffeId,
	})

	storeName, metadata, err := getStoreNameWithMetadata(entry.Selectors)
	if err != nil {
		log.WithError(err).Error("Invalid store name in selectors")
		return false
	}

	log = log.WithField(telemetry.SVIDStore, storeName)
	svidStore, ok := s.cat.GetSVIDStoreNamed(storeName)
	if !ok {
		log.Error("Error deleting SVID: SVIDStore not found")
		return false
	}

	err = svidStore.DeleteX509SVID(ctx, metadata)

	switch status.Code(err) {
	case codes.OK:
		log.Debug("SVID deleted successfully")
		return true

	case codes.InvalidArgument:
		log.WithError(err).Debug("Failed to delete SVID because of malformed selectors")
		return true

	default:
		log.WithError(err).Error("Failed to delete SVID")
		return false
	}
}

// storeSVID creates or updates an SVID using SVIDStore plugin. It get the plugin name from entry selectors
func (s *SVIDStoreService) storeSVID(ctx context.Context, log logrus.FieldLogger, record *storecache.Record) {
	if record.Svid == nil {
		// Svid is not yet provided.
		return
	}
	log = log.WithFields(logrus.Fields{
		telemetry.Entry:    record.Entry.EntryId,
		telemetry.SPIFFEID: record.Entry.SpiffeId,
	})

	storeName, metadata, err := getStoreNameWithMetadata(record.Entry.Selectors)
	if err != nil {
		log.WithError(err).Error("Invalid store name in selectors")
		return
	}

	log = log.WithField(telemetry.SVIDStore, storeName)
	svidStore, ok := s.cat.GetSVIDStoreNamed(storeName)
	if !ok {
		log.Error("Error storing SVID: SVIDStore not found")
		return
	}

	req, err := s.requestFromRecord(record, metadata)
	if err != nil {
		log.WithError(err).Error("Failed to parse record")
		return
	}

	if err := svidStore.PutX509SVID(ctx, req); err != nil {
		log.WithError(err).Error("Failed to put X509-SVID")
		return
	}

	// Set revision, since SVID was updated successfully
	s.cache.HandledRecord(record.Entry, record.Revision)
	log.Debug("SVID stored successfully")
}

// TODO: may we change log.Error for debug?
func (s *SVIDStoreService) processRecords(ctx context.Context) {
	counter := telemetry_store.StartStoreSVIDUpdates(s.metrics)
	defer counter.Done(nil)

	for _, record := range s.cache.ReadyToStore() {
		log := s.log.WithField(telemetry.RevisionNumber, record.Revision)

		// Check if entry is marked to be deleted
		if record.Entry == nil {
			// TODO: add a retry backoff
			if s.deleteSVID(ctx, log, record.HandledEntry) {
				// Deleted successfully. update revision
				s.cache.HandledRecord(record.HandledEntry, record.Revision)
			}
			continue
		}

		// Entries with changes on selectors must be removed before SVID is stored.
		if record.HandledEntry != nil {
			// Verify if selector changed. If it changed, delete the SVID from store before updating
			if !util.EqualsSelectors(record.Entry.Selectors, record.HandledEntry.Selectors) {
				// TODO: add retry, and maybe fail update until it is deleted?
				s.deleteSVID(ctx, log, record.HandledEntry)
			}
		}

		s.storeSVID(ctx, log, record)
	}
	if s.hooks.storeFinished != nil {
		s.hooks.storeFinished <- struct{}{}
	}
}

// requestFromRecord parses a cache record to a *svidstore.X509SVID
func (s *SVIDStoreService) requestFromRecord(record *storecache.Record, metadata []string) (*svidstore.X509SVID, error) {
	rootCA, ok := record.Bundles[s.trustDomain]
	if !ok {
		return nil, errors.New("no rootCA found")
	}

	federatedBundles := make(map[string][]*x509.Certificate)
	for _, federatedID := range record.Entry.FederatesWith {
		td, err := spiffeid.TrustDomainFromString(federatedID)
		if err != nil {
			// This is purely defensive since federatedID should be valid
			continue
		}

		// Do not add the agent's trust domain to the federated bundles
		if td == s.trustDomain {
			continue
		}

		bundle, ok := record.Bundles[td]
		if !ok {
			// Federated bundle not found, no action taken
			continue
		}

		federatedBundles[federatedID] = bundle.X509Authorities()
	}

	spiffeID, err := spiffeid.FromString(record.Entry.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE ID: %w", err)
	}

	return &svidstore.X509SVID{
		Metadata: metadata,
		SVID: &svidstore.SVID{
			SPIFFEID:   spiffeID,
			Bundle:     rootCA.X509Authorities(),
			CertChain:  record.Svid.Chain,
			PrivateKey: record.Svid.PrivateKey,
			ExpiresAt:  record.ExpiresAt,
		},
		FederatedBundles: federatedBundles,
	}, nil
}

// getStoreNameWithMetadata gets SVIDStore plugin name from entry selectors and selectors metadata, it fails in case an entry
func getStoreNameWithMetadata(selectors []*common.Selector) (string, []string, error) {
	if len(selectors) == 0 {
		return "", nil, errors.New("no selectors found")
	}

	var metadata []string
	name := selectors[0].Type
	for _, s := range selectors {
		if name != s.Type {
			return "", nil, errors.New("selector contains multiple types")
		}
		metadata = append(metadata, s.Value)
	}
	return name, metadata, nil
}
