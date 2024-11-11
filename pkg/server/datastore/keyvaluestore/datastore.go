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
	agents                  *record.Wrapper[agentCodec, *agentIndex, agentObject, *listAttestedNodes]
	bundles                 *record.Wrapper[bundleCodec, *bundleIndex, bundleObject, *datastore.ListBundlesRequest]
	entries                 *record.Wrapper[entryCodec, *entryIndex, entryObject, *listRegistrationEntries]
	joinTokens              *record.Wrapper[joinTokenCodec, *joinTokenIndex, joinTokenObject, *listJoinTokens]
	federationRelationships *record.Wrapper[federationRelationshipCodec, *federationRelationshipIndex, federationRelationshipObject, *datastore.ListFederationRelationshipsRequest]
	entriesEvents           *record.Wrapper[entryEventCodec, *entryEventIndex, entryEventObject, *listRegistrationEntryEventsRequest]
	nodeEvents              *record.Wrapper[nodeEventCodec, *nodeEventIndex, nodeEventObject, *listAttestedNodeEventsRequest]
	caJournal               *record.Wrapper[caJournalCodec, *caJournalIndex, caJournalObject, *listCaJournals]
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
	ds.agents = record.NewWrapper[agentCodec, *agentIndex, agentObject, *listAttestedNodes](store, "agent", new(agentIndex))
	ds.bundles = record.NewWrapper[bundleCodec, *bundleIndex, bundleObject, *datastore.ListBundlesRequest](store, "bundle", new(bundleIndex))
	ds.entries = record.NewWrapper[entryCodec, *entryIndex, entryObject, *listRegistrationEntries](store, "entry", new(entryIndex))
	ds.joinTokens = record.NewWrapper[joinTokenCodec, *joinTokenIndex, joinTokenObject, *listJoinTokens](store, "joinToken", new(joinTokenIndex))
	ds.federationRelationships = record.NewWrapper[federationRelationshipCodec, *federationRelationshipIndex, federationRelationshipObject, *datastore.ListFederationRelationshipsRequest](store, "federationRelationship", new(federationRelationshipIndex))
	ds.entriesEvents = record.NewWrapper[entryEventCodec, *entryEventIndex, entryEventObject, *listRegistrationEntryEventsRequest](store, "entriesEvents", new(entryEventIndex))
	ds.nodeEvents = record.NewWrapper[nodeEventCodec, *nodeEventIndex, nodeEventObject, *listAttestedNodeEventsRequest](store, "nodeEvents", new(nodeEventIndex))
	ds.caJournal = record.NewWrapper[caJournalCodec, *caJournalIndex, caJournalObject, *listCaJournals](store, "caJournal", new(caJournalIndex))

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
