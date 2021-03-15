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
)

const (
	defaultInterval = 5 * time.Second
)

type Cache interface {
	// ReadyToStore list of store cache records that are ready to be stored on specific SVID Store
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
	// trustDomain is the agents trust domain
	trustDomain spiffeid.TrustDomain
	// cache is the store cache
	cache Cache
	// svidStores is the allowed list of SVID Stores configured on agent
	svidStores map[string]svidstore.SVIDStore
	metrics    telemetry.Metrics

	hooks struct {
		// test hook used to verify a cycle finished
		storeFinished chan struct{}
	}
}

func New(c *Config) *SVIDStoreService {
	clk := c.Clk
	if clk == nil {
		clk = clock.New()
	}

	svidStores := make(map[string]svidstore.SVIDStore)
	for _, store := range c.Catalog.GetSVIDStores() {
		svidStores[store.Name()] = store
	}

	return &SVIDStoreService{
		cache:       c.Cache,
		clk:         clk,
		log:         c.Log,
		metrics:     c.Metrics,
		trustDomain: c.TrustDomain,
		svidStores:  svidStores,
	}
}

// SetStoreFinishedHook used for testing only
func (s *SVIDStoreService) SetStoreFinishedHook(storeFinished chan struct{}) {
	s.hooks.storeFinished = storeFinished
}

// Run starts SVID Store service
func (s *SVIDStoreService) Run(ctx context.Context) error {
	// TODO: may we run a StoreSVID when `Run` start?
	s.processRecords(ctx)

	ticker := s.clk.Ticker(defaultInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.processRecords(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

// deleteSVID deletes a secret using SVIDStore plugin, it gets plugin name from entry selectors
func (s *SVIDStoreService) deleteSVID(ctx context.Context, log logrus.FieldLogger, entry *common.RegistrationEntry) bool {
	log = log.WithField(telemetry.Entry, entry.EntryId)

	storeName, err := getStoreName(entry.Selectors)
	if err != nil {
		log.WithError(err).Error("selector contains invalid store name")
		return false
	}

	log = log.WithField(telemetry.SVIDStore, storeName)
	svidStore, ok := s.svidStores[storeName]
	if !ok {
		log.Error("Error deleting SVID: SVIDStore not found")
		return false
	}

	var secretData []string
	for _, selector := range entry.Selectors {
		secretData = append(secretData, selector.Value)
	}
	if err := svidStore.DeleteX509SVID(ctx, secretData); err != nil {
		log.WithError(err).Error("failed to delete secret")
		return false
	}

	log.Debug("Secret deleted successfully")
	return true
}

// storeSVID creates or update a secret using SVIDStore plugin, it gets plugin name from entry selectors
func (s *SVIDStoreService) storeSVID(ctx context.Context, log logrus.FieldLogger, record *storecache.Record) {
	if record.Svid == nil {
		// Svid is not yet provided.
		return
	}
	log = log.WithField(telemetry.Entry, record.Entry.EntryId)

	storeName, err := getStoreName(record.Entry.Selectors)
	if err != nil {
		log.WithError(err).Error("selector contains invalid store name")
		return
	}

	log = log.WithField(telemetry.SVIDStore, storeName)
	svidStore, ok := s.svidStores[storeName]
	if !ok {
		log.Error("Error storing SVID: SVIDStore not found")
		return
	}

	req, err := s.requestFromRecord(record)
	if err != nil {
		log.WithError(err).Error("failed to parse record")
		return
	}

	if err := svidStore.PutX509SVID(ctx, req); err != nil {
		log.WithError(err).Error("failed to Put X509-SVID")
		return
	}

	// Set revision, since secret was updated successfully
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

		// Entries with changes on selectors must be removed before secret is stored.
		if record.HandledEntry != nil {
			// Verify if selector change, and if it changes delete secret from store before update
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

// parseUpdate parses an SVID Update into a *svidstore.PutX509SVIDRequest request
func (s *SVIDStoreService) requestFromRecord(record *storecache.Record) (*svidstore.X509SVID, error) {
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

		// Prevent adding Trust Domain bundle a federated bundle
		if td == s.trustDomain {
			continue
		}

		bundle, ok := record.Bundles[td]
		if !ok {
			// Federated bundle not found, no action taken
			continue
		}

		federatedBundles[federatedID] = bundle.RootCAs()
	}

	var secretData []string
	for _, selector := range record.Entry.Selectors {
		secretData = append(secretData, selector.Value)
	}

	spiffeID, err := spiffeid.FromString(record.Entry.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE ID: %w", err)
	}

	return &svidstore.X509SVID{
		SecretsData: secretData,
		SVID: &svidstore.SVID{
			SpiffeID:   spiffeID,
			Bundle:     rootCA.RootCAs(),
			CertChain:  record.Svid.Chain,
			PrivateKey: record.Svid.PrivateKey,
			ExpiresAt:  record.ExpiresAt,
		},
		FederatedBundles: federatedBundles,
	}, nil
}

// getStoreName gets SVIDStore plugin name from entry selectors, it will fails in case an entry
// contains selectors with different types
func getStoreName(selectors []*common.Selector) (string, error) {
	if len(selectors) == 0 {
		return "", errors.New("no selectors found")
	}

	name := selectors[0].Type
	for _, s := range selectors {
		if name != s.Type {
			return "", errors.New("selector contains multiple types")
		}
	}
	return name, nil
}
