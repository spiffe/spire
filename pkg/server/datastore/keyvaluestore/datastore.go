package keyvaluestore

import (
	"context"
	"fmt"
	"unicode"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue/dynamostore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
)

const (
	PluginName = "keyvalue"
)

var (
	kvError           = errs.Class("datastore-keyvalue")
	validEntryIDChars = &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x002d, 0x002e, 1}, // - | .
			{0x0030, 0x0039, 1}, // [0-9]
			{0x0041, 0x005a, 1}, // [A-Z]
			{0x005f, 0x005f, 1}, // _
			{0x0061, 0x007a, 1}, // [a-z]
		},
		LatinOffset: 5,
	}
)

type Configuration struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	Endpoint        string `hcl:"endpoint" json:"endpoint"`
	TableName       string `hcl:"table_name" json:"table_name"`
}

type DataStore struct {
	datastore.DataStore

	log                     logrus.FieldLogger
	store                   keyvalue.Store
	agents                  *record.Cache[agentCodec, *agentIndex, agentObject, *listAttestedNodes]
	bundles                 *record.Cache[bundleCodec, *bundleIndex, bundleObject, *datastore.ListBundlesRequest]
	entries                 *record.Cache[entryCodec, *entryIndex, entryObject, *listRegistrationEntries]
	joinTokens              *record.Cache[joinTokenCodec, *joinTokenIndex, joinTokenObject, *listJoinTokens]
	federationRelationships *record.Cache[federationRelationshipCodec, *federationRelationshipIndex, federationRelationshipObject, *datastore.ListFederationRelationshipsRequest]
	entriesEvents           *record.Cache[entryEventCodec, *entryEventIndex, entryEventObject, *listRegistrationEntryEventsRequest]
	nodeEvents              *record.Cache[nodeEventCodec, *nodeEventIndex, nodeEventObject, *listAttestedNodeEventsRequest]
	caJournal               *record.Cache[caJournalCodec, *caJournalIndex, caJournalObject, *listCaJournals]
}

func New(log logrus.FieldLogger) *DataStore {
	return &DataStore{
		log: log,
	}
}

func (ds *DataStore) Configure(ctx context.Context, hclConfiguration string) error {
	config := &Configuration{}
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return err
	}

	store, err := dynamostore.Open(ctx, dynamostore.Config{
		AccessKeyID:     config.AccessKeyID,
		SecretAccessKey: config.SecretAccessKey,
		Region:          config.Region,
		Endpoint:        config.Endpoint,
		TableName:       config.TableName,
	})

	if err != nil {
		return fmt.Errorf("unable to open store: %w", err)
	}

	ds.store = store
	ds.agents = record.NewCache[agentCodec, *agentIndex, agentObject, *listAttestedNodes](store, "agent", new(agentIndex))
	ds.bundles = record.NewCache[bundleCodec, *bundleIndex, bundleObject, *datastore.ListBundlesRequest](store, "bundle", new(bundleIndex))
	ds.entries = record.NewCache[entryCodec, *entryIndex, entryObject, *listRegistrationEntries](store, "entry", new(entryIndex))
	ds.joinTokens = record.NewCache[joinTokenCodec, *joinTokenIndex, joinTokenObject, *listJoinTokens](store, "joinToken", new(joinTokenIndex))
	ds.federationRelationships = record.NewCache[federationRelationshipCodec, *federationRelationshipIndex, federationRelationshipObject, *datastore.ListFederationRelationshipsRequest](store, "federationRelationship", new(federationRelationshipIndex))
	ds.entriesEvents = record.NewCache[entryEventCodec, *entryEventIndex, entryEventObject, *listRegistrationEntryEventsRequest](store, "entriesEvents", new(entryEventIndex))
	ds.nodeEvents = record.NewCache[nodeEventCodec, *nodeEventIndex, nodeEventObject, *listAttestedNodeEventsRequest](store, "nodeEvents", new(nodeEventIndex))
	ds.caJournal = record.NewCache[caJournalCodec, *caJournalIndex, caJournalObject, *listCaJournals](store, "caJournal", new(caJournalIndex))

	return err
}

func (ds *DataStore) Close() error {
	var closeErr error

	if err := ds.store.Close(); err != nil {
		if closeErr != nil {
			closeErr = err
		}
	}

	return closeErr
}
