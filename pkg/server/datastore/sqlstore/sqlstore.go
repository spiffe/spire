package sqlstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	sqlError          = errs.Class("datastore-sql")
	validationError   = errs.Class("datastore-validation")
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

const (
	PluginName = "sql"

	// MySQL database type
	MySQL = "mysql"
	// PostgreSQL database type
	PostgreSQL = "postgres"
	// SQLite database type
	SQLite = "sqlite3"

	// MySQL database provided by an AWS service
	AWSMySQL = "aws_mysql"

	// PostgreSQL database type provided by an AWS service
	AWSPostgreSQL = "aws_postgres"

	// Maximum size for preallocation in a paginated request
	maxResultPreallocation = 1000
)

// Configuration for the sql datastore implementation.
// Pointer values are used to distinguish between "unset" and "zero" values.
type configuration struct {
	DatabaseTypeNode   ast.Node `hcl:"database_type" json:"database_type"`
	ConnectionString   string   `hcl:"connection_string" json:"connection_string"`
	RoConnectionString string   `hcl:"ro_connection_string" json:"ro_connection_string"`
	RootCAPath         string   `hcl:"root_ca_path" json:"root_ca_path"`
	ClientCertPath     string   `hcl:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath      string   `hcl:"client_key_path" json:"client_key_path"`
	ConnMaxLifetime    *string  `hcl:"conn_max_lifetime" json:"conn_max_lifetime"`
	MaxOpenConns       *int     `hcl:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns       *int     `hcl:"max_idle_conns" json:"max_idle_conns"`
	DisableMigration   bool     `hcl:"disable_migration" json:"disable_migration"`

	databaseTypeConfig *dbTypeConfig
	// Undocumented flags
	LogSQL bool `hcl:"log_sql" json:"log_sql"`
}

type dbTypeConfig struct {
	AWSMySQL     *awsConfig `hcl:"aws_mysql" json:"aws_mysql"`
	AWSPostgres  *awsConfig `hcl:"aws_postgres" json:"aws_postgres"`
	databaseType string
}

type awsConfig struct {
	Region          string `hcl:"region"`
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
}

func (a *awsConfig) validate() error {
	if a.Region == "" {
		return sqlError.New("region must be specified")
	}
	return nil
}

type sqlDB struct {
	databaseType     string
	connectionString string
	raw              *sql.DB
	*gorm.DB

	dialect     dialect
	stmtCache   *stmtCache
	supportsCTE bool

	// this lock is only required for synchronized writes with "sqlite3". see
	// the withTx() implementation for details.
	opMu sync.Mutex
}

func (db *sqlDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	stmt, err := db.stmtCache.get(ctx, query)
	if err != nil {
		return nil, err
	}
	return stmt.QueryContext(ctx, args...)
}

// Plugin is a DataStore plugin implemented via a SQL database
type Plugin struct {
	mu                  sync.Mutex
	db                  *sqlDB
	roDb                *sqlDB
	log                 logrus.FieldLogger
	useServerTimestamps bool
}

// New creates a new sql plugin struct. Configure must be called
// in order to start the db.
func New(log logrus.FieldLogger) *Plugin {
	return &Plugin{
		log: log,
	}
}

// CreateBundle stores the given bundle
func (ds *Plugin) CreateBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = createBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *Plugin) UpdateBundle(ctx context.Context, b *common.Bundle, mask *common.BundleMask) (bundle *common.Bundle, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = updateBundle(tx, b, mask)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *Plugin) SetBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = setBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *Plugin) AppendBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = appendBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *Plugin) DeleteBundle(ctx context.Context, trustDomainID string, mode datastore.DeleteMode) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = deleteBundle(tx, trustDomainID, mode)
		return err
	})
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *Plugin) FetchBundle(ctx context.Context, trustDomainID string) (resp *common.Bundle, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, trustDomainID)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CountBundles can be used to count all existing bundles.
func (ds *Plugin) CountBundles(ctx context.Context) (count int32, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		count, err = countBundles(tx)
		return err
	}); err != nil {
		return 0, err
	}
	return count, nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *Plugin) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (resp *datastore.ListBundlesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listBundles(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneBundle removes expired certs and keys from a bundle
func (ds *Plugin) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		changed, err = pruneBundle(tx, trustDomainID, expiresBefore, ds.log)
		return err
	}); err != nil {
		return false, err
	}

	return changed, nil
}

// TaintX509CAByKey taints an X.509 CA signed using the provided public key
func (ds *Plugin) TaintX509CA(ctx context.Context, trustDoaminID string, subjectKeyIDToTaint string) error {
	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return taintX509CA(tx, trustDoaminID, subjectKeyIDToTaint)
	})
}

// RevokeX509CA removes a Root CA from the bundle
func (ds *Plugin) RevokeX509CA(ctx context.Context, trustDoaminID string, subjectKeyIDToRevoke string) error {
	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return revokeX509CA(tx, trustDoaminID, subjectKeyIDToRevoke)
	})
}

// TaintJWTKey taints a JWT Authority key
func (ds *Plugin) TaintJWTKey(ctx context.Context, trustDoaminID string, authorityID string) (*common.PublicKey, error) {
	var taintedKey *common.PublicKey
	if err := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		taintedKey, err = taintJWTKey(tx, trustDoaminID, authorityID)
		return err
	}); err != nil {
		return nil, err
	}
	return taintedKey, nil
}

// RevokeJWTAuthority removes JWT key from the bundle
func (ds *Plugin) RevokeJWTKey(ctx context.Context, trustDoaminID string, authorityID string) (*common.PublicKey, error) {
	var revokedKey *common.PublicKey
	if err := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		revokedKey, err = revokeJWTKey(tx, trustDoaminID, authorityID)
		return err
	}); err != nil {
		return nil, err
	}
	return revokedKey, nil
}

// CreateAttestedNode stores the given attested node
func (ds *Plugin) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (attestedNode *common.AttestedNode, err error) {
	if node == nil {
		return nil, sqlError.New("invalid request: missing attested node")
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = createAttestedNode(tx, node)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{
			SpiffeID: node.SpiffeId,
		})
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

// FetchAttestedNode fetches an existing attested node by SPIFFE ID
func (ds *Plugin) FetchAttestedNode(ctx context.Context, spiffeID string) (attestedNode *common.AttestedNode, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = fetchAttestedNode(tx, spiffeID)
		return err
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

// CountAttestedNodes counts all attested nodes
func (ds *Plugin) CountAttestedNodes(ctx context.Context, req *datastore.CountAttestedNodesRequest) (count int32, err error) {
	if countAttestedNodesHasFilters(req) {
		resp, err := countAttestedNodesWithFilters(ctx, ds.db, ds.log, req)
		return resp, err
	}
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		count, err = countAttestedNodes(tx)
		return err
	}); err != nil {
		return 0, err
	}

	return count, nil
}

// ListAttestedNodes lists all attested nodes (pagination available)
func (ds *Plugin) ListAttestedNodes(ctx context.Context,
	req *datastore.ListAttestedNodesRequest,
) (resp *datastore.ListAttestedNodesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodes(ctx, ds.db, ds.log, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateAttestedNode updates the given node's cert serial and expiration.
func (ds *Plugin) UpdateAttestedNode(ctx context.Context, n *common.AttestedNode, mask *common.AttestedNodeMask) (node *common.AttestedNode, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		node, err = updateAttestedNode(tx, n, mask)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{
			SpiffeID: n.SpiffeId,
		})
	}); err != nil {
		return nil, err
	}
	return node, nil
}

// DeleteAttestedNode deletes the given attested node and the associated node selectors.
func (ds *Plugin) DeleteAttestedNode(ctx context.Context, spiffeID string) (attestedNode *common.AttestedNode, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = deleteAttestedNodeAndSelectors(tx, spiffeID)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{
			SpiffeID: spiffeID,
		})
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

// ListAttestedNodeEvents lists all attested node events
func (ds *Plugin) ListAttestedNodeEvents(ctx context.Context, req *datastore.ListAttestedNodeEventsRequest) (resp *datastore.ListAttestedNodeEventsResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodeEvents(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneAttestedNodeEvents deletes all attested node events older than a specified duration (i.e. more than 24 hours old)
func (ds *Plugin) PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = pruneAttestedNodeEvents(tx, olderThan)
		return err
	})
}

// CreateRegistrationEntryEventForTestingForTesting creates an attested node event. Used for unit testing.
func (ds *Plugin) CreateAttestedNodeEventForTesting(ctx context.Context, event *datastore.AttestedNodeEvent) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return createAttestedNodeEvent(tx, event)
	})
}

// DeleteAttestedNodeEventForTesting deletes an attested node event by event ID. Used for unit testing.
func (ds *Plugin) DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return deleteAttestedNodeEvent(tx, eventID)
	})
}

// FetchAttestedNodeEvent fetches an existing attested node event by event ID
func (ds *Plugin) FetchAttestedNodeEvent(ctx context.Context, eventID uint) (event *datastore.AttestedNodeEvent, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		event, err = fetchAttestedNodeEvent(ds.db, eventID)
		return err
	}); err != nil {
		return nil, err
	}

	return event, nil
}

// SetNodeSelectors sets node (agent) selectors by SPIFFE ID, deleting old selectors first
func (ds *Plugin) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		if err = setNodeSelectors(tx, spiffeID, selectors); err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{
			SpiffeID: spiffeID,
		})
	})
}

// GetNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *Plugin) GetNodeSelectors(ctx context.Context, spiffeID string,
	dataConsistency datastore.DataConsistency,
) (selectors []*common.Selector, err error) {
	if dataConsistency == datastore.TolerateStale && ds.roDb != nil {
		return getNodeSelectors(ctx, ds.roDb, spiffeID)
	}
	return getNodeSelectors(ctx, ds.db, spiffeID)
}

// ListNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *Plugin) ListNodeSelectors(ctx context.Context,
	req *datastore.ListNodeSelectorsRequest,
) (resp *datastore.ListNodeSelectorsResponse, err error) {
	if req.DataConsistency == datastore.TolerateStale && ds.roDb != nil {
		return listNodeSelectors(ctx, ds.roDb, req)
	}
	return listNodeSelectors(ctx, ds.db, req)
}

// CreateRegistrationEntry stores the given registration entry
func (ds *Plugin) CreateRegistrationEntry(ctx context.Context,
	entry *common.RegistrationEntry,
) (registrationEntry *common.RegistrationEntry, err error) {
	out, _, err := ds.createOrReturnRegistrationEntry(ctx, entry)
	return out, err
}

// CreateOrReturnRegistrationEntry stores the given registration entry. If an
// entry already exists with the same (parentID, spiffeID, selector) tuple,
// that entry is returned instead.
func (ds *Plugin) CreateOrReturnRegistrationEntry(ctx context.Context,
	entry *common.RegistrationEntry,
) (registrationEntry *common.RegistrationEntry, existing bool, err error) {
	return ds.createOrReturnRegistrationEntry(ctx, entry)
}

func (ds *Plugin) createOrReturnRegistrationEntry(ctx context.Context,
	entry *common.RegistrationEntry,
) (registrationEntry *common.RegistrationEntry, existing bool, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		if err = validateRegistrationEntry(entry); err != nil {
			return err
		}

		registrationEntry, err = lookupSimilarEntry(ctx, ds.db, tx, entry)
		if err != nil {
			return err
		}
		if registrationEntry != nil {
			existing = true
			return nil
		}
		registrationEntry, err = createRegistrationEntry(tx, entry)
		if err != nil {
			return err
		}

		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{
			EntryID: registrationEntry.EntryId,
		})
	}); err != nil {
		return nil, false, err
	}
	return registrationEntry, existing, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
func (ds *Plugin) FetchRegistrationEntry(ctx context.Context,
	entryID string,
) (*common.RegistrationEntry, error) {
	return fetchRegistrationEntry(ctx, ds.db, entryID)
}

// CountRegistrationEntries counts all registrations (pagination available)
func (ds *Plugin) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (count int32, err error) {
	actDb := ds.db
	if req.DataConsistency == datastore.TolerateStale && ds.roDb != nil {
		actDb = ds.roDb
	}

	resp, err := countRegistrationEntries(ctx, actDb, ds.log, req)
	return resp, err
}

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *Plugin) ListRegistrationEntries(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest,
) (resp *datastore.ListRegistrationEntriesResponse, err error) {
	if req.DataConsistency == datastore.TolerateStale && ds.roDb != nil {
		return listRegistrationEntries(ctx, ds.roDb, ds.log, req)
	}
	return listRegistrationEntries(ctx, ds.db, ds.log, req)
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *Plugin) UpdateRegistrationEntry(ctx context.Context, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (entry *common.RegistrationEntry, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		entry, err = updateRegistrationEntry(tx, e, mask)
		if err != nil {
			return err
		}

		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{
			EntryID: entry.EntryId,
		})
	}); err != nil {
		return nil, err
	}
	return entry, nil
}

// DeleteRegistrationEntry deletes the given registration
func (ds *Plugin) DeleteRegistrationEntry(ctx context.Context,
	entryID string,
) (registrationEntry *common.RegistrationEntry, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		registrationEntry, err = deleteRegistrationEntry(tx, entryID)
		if err != nil {
			return err
		}

		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{
			EntryID: entryID,
		})
	}); err != nil {
		return nil, err
	}
	return registrationEntry, nil
}

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
// before the date in the message
func (ds *Plugin) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = pruneRegistrationEntries(tx, expiresBefore, ds.log)
		return err
	})
}

// ListRegistrationEntryEvents lists all registration entry events
func (ds *Plugin) ListRegistrationEntryEvents(ctx context.Context, req *datastore.ListRegistrationEntryEventsRequest) (resp *datastore.ListRegistrationEntryEventsResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listRegistrationEntryEvents(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneRegistrationEntryEvents deletes all registration entry events older than a specified duration (i.e. more than 24 hours old)
func (ds *Plugin) PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = pruneRegistrationEntryEvents(tx, olderThan)
		return err
	})
}

// CreateRegistrationEntryEventForTesting creates a registration entry event. Used for unit testing.
func (ds *Plugin) CreateRegistrationEntryEventForTesting(ctx context.Context, event *datastore.RegistrationEntryEvent) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return createRegistrationEntryEvent(tx, event)
	})
}

// DeleteRegistrationEntryEventForTesting deletes the given registration entry event. Used for unit testing.
func (ds *Plugin) DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return deleteRegistrationEntryEvent(tx, eventID)
	})
}

// FetchRegistrationEntryEvent fetches an existing registration entry event by event ID
func (ds *Plugin) FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (event *datastore.RegistrationEntryEvent, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		event, err = fetchRegistrationEntryEvent(ds.db, eventID)
		return err
	}); err != nil {
		return nil, err
	}

	return event, nil
}

// CreateJoinToken takes a Token message and stores it
func (ds *Plugin) CreateJoinToken(ctx context.Context, token *datastore.JoinToken) (err error) {
	if token == nil || token.Token == "" || token.Expiry.IsZero() {
		return errors.New("token and expiry are required")
	}

	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = createJoinToken(tx, token)
		return err
	})
}

// FetchJoinToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (ds *Plugin) FetchJoinToken(ctx context.Context, token string) (resp *datastore.JoinToken, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchJoinToken(tx, token)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteJoinToken deletes the given join token
func (ds *Plugin) DeleteJoinToken(ctx context.Context, token string) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = deleteJoinToken(tx, token)
		return err
	})
}

// PruneJoinTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *Plugin) PruneJoinTokens(ctx context.Context, expiry time.Time) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = pruneJoinTokens(tx, expiry)
		return err
	})
}

// CreateFederationRelationship creates a new federation relationship. If the bundle endpoint
// profile is 'https_spiffe' and the given federation relationship contains a bundle, the current
// stored bundle is overridden.
// If no bundle is provided and there is not a previously stored bundle in the datastore, the
// federation relationship is not created.
func (ds *Plugin) CreateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship) (newFr *datastore.FederationRelationship, err error) {
	if err := validateFederationRelationship(fr, protoutil.AllTrueFederationRelationshipMask); err != nil {
		return nil, err
	}

	return newFr, ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		newFr, err = createFederationRelationship(tx, fr)
		return err
	})
}

// DeleteFederationRelationship deletes the federation relationship to the
// given trust domain. The associated trust bundle is not deleted.
func (ds *Plugin) DeleteFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) error {
	if trustDomain.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = deleteFederationRelationship(tx, trustDomain)
		return err
	})
}

// FetchFederationRelationship fetches the federation relationship that matches
// the given trust domain. If the federation relationship is not found, nil is returned.
func (ds *Plugin) FetchFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) (fr *datastore.FederationRelationship, err error) {
	if trustDomain.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		fr, err = fetchFederationRelationship(tx, trustDomain)
		return err
	}); err != nil {
		return nil, err
	}

	return fr, nil
}

// ListFederationRelationships can be used to list all existing federation relationships
func (ds *Plugin) ListFederationRelationships(ctx context.Context, req *datastore.ListFederationRelationshipsRequest) (resp *datastore.ListFederationRelationshipsResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listFederationRelationships(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateFederationRelationship updates the given federation relationship.
// Attributes are only updated if the correspondent mask value is set to true.
func (ds *Plugin) UpdateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (newFr *datastore.FederationRelationship, err error) {
	if err := validateFederationRelationship(fr, mask); err != nil {
		return nil, err
	}

	return newFr, ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) error {
		newFr, err = updateFederationRelationship(tx, fr, mask)
		return err
	})
}

// SetUseServerTimestamps controls whether server-generated timestamps should be used in the database.
// This is only intended to be used by tests in order to produce deterministic timestamp data,
// since some databases round off timestamp data with lower precision.
func (ds *Plugin) SetUseServerTimestamps(useServerTimestamps bool) {
	ds.useServerTimestamps = useServerTimestamps
}

// FetchCAJournal fetches the CA journal that has the given active X509
// authority domain. If the CA journal is not found, nil is returned.
func (ds *Plugin) FetchCAJournal(ctx context.Context, activeX509AuthorityID string) (caJournal *datastore.CAJournal, err error) {
	if activeX509AuthorityID == "" {
		return nil, status.Error(codes.InvalidArgument, "active X509 authority ID is required")
	}

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		caJournal, err = fetchCAJournal(tx, activeX509AuthorityID)
		return err
	}); err != nil {
		return nil, err
	}

	return caJournal, nil
}

// ListCAJournalsForTesting returns all the CA journal records, and is meant to
// be used in tests.
func (ds *Plugin) ListCAJournalsForTesting(ctx context.Context) (caJournals []*datastore.CAJournal, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		caJournals, err = listCAJournalsForTesting(tx)
		return err
	}); err != nil {
		return nil, err
	}
	return caJournals, nil
}

// SetCAJournal sets the content for the specified CA journal. If the CA journal
// does not exist, it is created.
func (ds *Plugin) SetCAJournal(ctx context.Context, caJournal *datastore.CAJournal) (caj *datastore.CAJournal, err error) {
	if err := validateCAJournal(caJournal); err != nil {
		return nil, err
	}

	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		if caJournal.ID == 0 {
			caj, err = createCAJournal(tx, caJournal)
			return err
		}

		// The CA journal already exists, update it.
		caj, err = updateCAJournal(tx, caJournal)
		return err
	}); err != nil {
		return nil, err
	}
	return caj, nil
}

// PruneCAJournals prunes the CA journals that have all of their authorities
// expired.
func (ds *Plugin) PruneCAJournals(ctx context.Context, allAuthoritiesExpireBefore int64) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = ds.pruneCAJournals(tx, allAuthoritiesExpireBefore)
		return err
	})
}

func (ds *Plugin) pruneCAJournals(tx *gorm.DB, allAuthoritiesExpireBefore int64) error {
	var caJournals []CAJournal
	if err := tx.Find(&caJournals).Error; err != nil {
		return sqlError.Wrap(err)
	}

checkAuthorities:
	for _, model := range caJournals {
		entries := new(journal.Entries)
		if err := proto.Unmarshal(model.Data, entries); err != nil {
			return status.Errorf(codes.Internal, "unable to unmarshal entries from CA journal record: %v", err)
		}

		for _, x509CA := range entries.X509CAs {
			if x509CA.NotAfter > allAuthoritiesExpireBefore {
				continue checkAuthorities
			}
		}
		for _, jwtKey := range entries.JwtKeys {
			if jwtKey.NotAfter > allAuthoritiesExpireBefore {
				continue checkAuthorities
			}
		}
		if err := deleteCAJournal(tx, model.ID); err != nil {
			return status.Errorf(codes.Internal, "failed to delete CA journal: %v", err)
		}
		ds.log.WithFields(logrus.Fields{
			telemetry.CAJournalID: model.ID,
		}).Info("Pruned stale CA journal record")
	}

	return nil
}

// Configure parses HCL config payload into config struct, opens new DB based on the result, and
// prunes all orphaned records
func (ds *Plugin) Configure(_ context.Context, hclConfiguration string) error {
	config := &configuration{}
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return err
	}

	dbTypeConfig, err := parseDatabaseTypeASTNode(config.DatabaseTypeNode)
	if err != nil {
		return err
	}

	config.databaseTypeConfig = dbTypeConfig

	if err := config.Validate(); err != nil {
		return err
	}

	return ds.openConnections(config)
}

func (ds *Plugin) openConnections(config *configuration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if err := ds.openConnection(config, false); err != nil {
		return err
	}

	if config.RoConnectionString == "" {
		return nil
	}

	return ds.openConnection(config, true)
}

func (ds *Plugin) openConnection(config *configuration, isReadOnly bool) error {
	connectionString := getConnectionString(config, isReadOnly)
	sqlDb := ds.db
	if isReadOnly {
		sqlDb = ds.roDb
	}

	if sqlDb == nil || connectionString != sqlDb.connectionString || config.databaseTypeConfig.databaseType != ds.db.databaseType {
		db, version, supportsCTE, dialect, err := ds.openDB(config, isReadOnly)
		if err != nil {
			return err
		}

		raw := db.DB()
		if raw == nil {
			return sqlError.New("unable to get raw database object")
		}

		if sqlDb != nil {
			sqlDb.Close()
		}

		ds.log.WithFields(logrus.Fields{
			telemetry.Type:     config.databaseTypeConfig.databaseType,
			telemetry.Version:  version,
			telemetry.ReadOnly: isReadOnly,
		}).Info("Connected to SQL database")

		sqlDb = &sqlDB{
			DB:               db,
			raw:              raw,
			databaseType:     config.databaseTypeConfig.databaseType,
			dialect:          dialect,
			connectionString: connectionString,
			stmtCache:        newStmtCache(raw),
			supportsCTE:      supportsCTE,
		}
	}

	if isReadOnly {
		ds.roDb = sqlDb
	} else {
		ds.db = sqlDb
	}

	sqlDb.LogMode(config.LogSQL)
	return nil
}

func (ds *Plugin) Close() error {
	var errs errs.Group
	if ds.db != nil {
		errs.Add(ds.db.Close())
	}

	if ds.roDb != nil {
		errs.Add(ds.roDb.Close())
	}
	return errs.Err()
}

// withReadModifyWriteTx wraps the operation in a transaction appropriate for
// operations that will read one or more rows, change one or more columns in
// those rows, and then set them back. This requires a stronger level of
// consistency that prevents two transactions from doing read-modify-write
// concurrently.
func (ds *Plugin) withReadModifyWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, func(tx *gorm.DB) error {
		switch {
		case isMySQLDbType(ds.db.databaseType):
			// MySQL REPEATABLE READ is weaker than that of PostgreSQL. Namely,
			// PostgreSQL, beyond providing the minimum consistency guarantees
			// mandated for REPEATABLE READ in the standard, automatically fails
			// concurrent transactions that try to update the same target row.
			//
			// To get the same consistency guarantees, have the queries do a
			// `SELECT .. FOR UPDATE` which will implicitly lock queried rows
			// from update by other transactions. This is preferred to a stronger
			// isolation level, like SERIALIZABLE, which is not supported by
			// some MySQL-compatible databases (i.e. Percona XtraDB cluster)
			tx = tx.Set("gorm:query_option", "FOR UPDATE")
		case isPostgresDbType(ds.db.databaseType):
			// `SELECT .. FOR UPDATE`is also required when PostgreSQL is in
			// hot standby mode for this operation to work properly (see issue #3039).
			tx = tx.Set("gorm:query_option", "FOR UPDATE")
		}
		return op(tx)
	}, false)
}

// withWriteTx wraps the operation in a transaction appropriate for operations
// that unconditionally create/update rows, without reading them first. If two
// transactions try and update at the same time, last writer wins.
func (ds *Plugin) withWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false)
}

// withReadTx wraps the operation in a transaction appropriate for operations
// that only read rows.
func (ds *Plugin) withReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, true)
}

func (ds *Plugin) withTx(ctx context.Context, op func(tx *gorm.DB) error, readOnly bool) error {
	ds.mu.Lock()
	db := ds.db
	ds.mu.Unlock()

	if db.databaseType == SQLite && !readOnly {
		// sqlite3 can only have one writer at a time. since we're in WAL mode,
		// there can be concurrent reads and writes, so no lock is necessary
		// over the read operations.
		db.opMu.Lock()
		defer db.opMu.Unlock()
	}

	tx := db.BeginTx(ctx, nil)
	if err := tx.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if err := op(tx); err != nil {
		tx.Rollback()
		return ds.gormToGRPCStatus(err)
	}

	if readOnly {
		// rolling back makes sure that functions that are invoked with
		// withReadTx, and then do writes, will not pass unit tests, since the
		// writes won't be committed.
		return sqlError.Wrap(tx.Rollback().Error)
	}
	return sqlError.Wrap(tx.Commit().Error)
}

// gormToGRPCStatus takes an error, and converts it to a GRPC error.  If the
// error is already a gRPC status , it will be returned unmodified. Otherwise
// if the error is a gorm error type with a known mapping to a GRPC status,
// that code will be set, otherwise the code will be set to Unknown.
func (ds *Plugin) gormToGRPCStatus(err error) error {
	unwrapped := errs.Unwrap(err)
	if _, ok := status.FromError(unwrapped); ok {
		return unwrapped
	}

	code := codes.Unknown
	if validationError.Has(err) {
		code = codes.InvalidArgument
	}

	switch {
	case gorm.IsRecordNotFoundError(unwrapped):
		code = codes.NotFound
	case ds.db.dialect.isConstraintViolation(unwrapped):
		code = codes.AlreadyExists
	default:
	}

	return status.Error(code, err.Error())
}

func (ds *Plugin) openDB(cfg *configuration, isReadOnly bool) (*gorm.DB, string, bool, dialect, error) {
	var dialect dialect

	ds.log.WithField(telemetry.DatabaseType, cfg.databaseTypeConfig.databaseType).Info("Opening SQL database")
	switch {
	case isSQLiteDbType(cfg.databaseTypeConfig.databaseType):
		dialect = sqliteDB{log: ds.log}
	case isPostgresDbType(cfg.databaseTypeConfig.databaseType):
		dialect = postgresDB{}
	case isMySQLDbType(cfg.databaseTypeConfig.databaseType):
		dialect = mysqlDB{
			logger: ds.log,
		}
	default:
		return nil, "", false, nil, sqlError.New("unsupported database_type: %v", cfg.databaseTypeConfig.databaseType)
	}

	db, version, supportsCTE, err := dialect.connect(cfg, isReadOnly)
	if err != nil {
		return nil, "", false, nil, sqlError.Wrap(err)
	}

	db.SetLogger(gormLogger{
		log: ds.log.WithField(telemetry.SubsystemName, "gorm"),
	})
	db.DB().SetMaxOpenConns(100) // default value
	if cfg.MaxOpenConns != nil {
		db.DB().SetMaxOpenConns(*cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != nil {
		db.DB().SetMaxIdleConns(*cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime != nil {
		connMaxLifetime, err := time.ParseDuration(*cfg.ConnMaxLifetime)
		if err != nil {
			return nil, "", false, nil, fmt.Errorf("failed to parse conn_max_lifetime %q: %w", *cfg.ConnMaxLifetime, err)
		}
		db.DB().SetConnMaxLifetime(connMaxLifetime)
	}
	if ds.useServerTimestamps {
		db.SetNowFuncOverride(func() time.Time {
			// Round to nearest second to be consistent with how timestamps are rounded in CreateRegistrationEntry calls
			return time.Now().Round(time.Second)
		})
	}

	if !isReadOnly {
		if err := migrateDB(db, cfg.databaseTypeConfig.databaseType, cfg.DisableMigration, ds.log); err != nil {
			db.Close()
			return nil, "", false, nil, err
		}
	}

	return db, version, supportsCTE, dialect, nil
}

type gormLogger struct {
	log logrus.FieldLogger
}

func (logger gormLogger) Print(v ...any) {
	logger.log.Debug(gorm.LogFormatter(v...)...)
}

func createBundle(tx *gorm.DB, bundle *common.Bundle) (*common.Bundle, error) {
	model, err := bundleToModel(bundle)
	if err != nil {
		return nil, err
	}

	if err := tx.Create(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return bundle, nil
}

func updateBundle(tx *gorm.DB, newBundle *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	newModel, err := bundleToModel(newBundle)
	if err != nil {
		return nil, err
	}

	model := &Bundle{}
	if err := tx.Find(model, "trust_domain = ?", newModel.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	model.Data, newBundle, err = applyBundleMask(model, newBundle, mask)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Save(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return newBundle, nil
}

func applyBundleMask(model *Bundle, newBundle *common.Bundle, inputMask *common.BundleMask) ([]byte, *common.Bundle, error) {
	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, nil, err
	}

	if inputMask == nil {
		inputMask = protoutil.AllTrueCommonBundleMask
	}

	if inputMask.RefreshHint {
		bundle.RefreshHint = newBundle.RefreshHint
	}

	if inputMask.RootCas {
		bundle.RootCas = newBundle.RootCas
	}

	if inputMask.JwtSigningKeys {
		bundle.JwtSigningKeys = newBundle.JwtSigningKeys
	}

	if inputMask.SequenceNumber {
		bundle.SequenceNumber = newBundle.SequenceNumber
	}

	newModel, err := bundleToModel(bundle)
	if err != nil {
		return nil, nil, err
	}

	return newModel.Data, bundle, nil
}

func setBundle(tx *gorm.DB, b *common.Bundle) (*common.Bundle, error) {
	newModel, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.RecordNotFound() {
		bundle, err := createBundle(tx, b)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	} else if result.Error != nil {
		return nil, sqlError.Wrap(result.Error)
	}

	bundle, err := updateBundle(tx, b, nil)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func appendBundle(tx *gorm.DB, b *common.Bundle) (*common.Bundle, error) {
	newModel, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.RecordNotFound() {
		bundle, err := createBundle(tx, b)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	} else if result.Error != nil {
		return nil, sqlError.Wrap(result.Error)
	}

	// parse the bundle data and add missing elements
	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	bundle, changed := bundleutil.MergeBundles(bundle, b)
	if changed {
		bundle.SequenceNumber++
		newModel, err := bundleToModel(bundle)
		if err != nil {
			return nil, err
		}
		model.Data = newModel.Data
		if err := tx.Save(model).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	return bundle, nil
}

func deleteBundle(tx *gorm.DB, trustDomainID string, mode datastore.DeleteMode) error {
	model := new(Bundle)
	if err := tx.Find(model, "trust_domain = ?", trustDomainID).Error; err != nil {
		return sqlError.Wrap(err)
	}

	// Get a count of associated registration entries
	entriesAssociation := tx.Model(model).Association("FederatedEntries")
	entriesCount := entriesAssociation.Count()
	if err := entriesAssociation.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if entriesCount > 0 {
		switch mode {
		case datastore.Delete:
			// TODO: figure out how to do this gracefully with GORM.
			if err := tx.Exec(bindVars(tx, `DELETE FROM registered_entries WHERE id in (
				SELECT
					registered_entry_id
				FROM
					federated_registration_entries
				WHERE
					bundle_id = ?)`), model.ID).Error; err != nil {
				return sqlError.Wrap(err)
			}
		case datastore.Dissociate:
			if err := entriesAssociation.Clear().Error; err != nil {
				return sqlError.Wrap(err)
			}
		default:
			return status.Newf(codes.FailedPrecondition, "datastore-sql: cannot delete bundle; federated with %d registration entries", entriesCount).Err()
		}
	}

	if err := tx.Delete(model).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

// fetchBundle returns the bundle matching the specified Trust Domain.
func fetchBundle(tx *gorm.DB, trustDomainID string) (*common.Bundle, error) {
	model := new(Bundle)
	err := tx.Find(model, "trust_domain = ?", trustDomainID).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

// countBundles can be used to count existing bundles
func countBundles(tx *gorm.DB) (int32, error) {
	tx = tx.Model(&Bundle{})

	var count int
	if err := tx.Count(&count).Error; err != nil {
		return 0, sqlError.Wrap(err)
	}

	return int32(count), nil
}

// listBundles can be used to fetch all existing bundles.
func listBundles(tx *gorm.DB, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	p := req.Pagination
	var err error
	if p != nil {
		tx, err = applyPagination(p, tx)
		if err != nil {
			return nil, err
		}
	}

	var bundles []Bundle
	if err := tx.Find(&bundles).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if p != nil {
		p.Token = ""
		// Set token only if page size is the same than bundles len
		if len(bundles) > 0 {
			lastEntry := bundles[len(bundles)-1]
			p.Token = fmt.Sprint(lastEntry.ID)
		}
	}

	resp := &datastore.ListBundlesResponse{
		Pagination: p,
	}
	for _, model := range bundles {
		model := model // alias the loop variable since we pass it by reference below
		bundle, err := modelToBundle(&model)
		if err != nil {
			return nil, err
		}

		resp.Bundles = append(resp.Bundles, bundle)
	}

	return resp, nil
}

func pruneBundle(tx *gorm.DB, trustDomainID string, expiry time.Time, log logrus.FieldLogger) (bool, error) {
	// Get current bundle
	currentBundle, err := fetchBundle(tx, trustDomainID)
	if err != nil {
		return false, fmt.Errorf("unable to fetch current bundle: %w", err)
	}

	if currentBundle == nil {
		// No bundle to prune
		return false, nil
	}

	// Prune
	newBundle, changed, err := bundleutil.PruneBundle(currentBundle, expiry, log)
	if err != nil {
		return false, fmt.Errorf("prune failed: %w", err)
	}

	// Update only if bundle was modified
	if changed {
		newBundle.SequenceNumber = currentBundle.SequenceNumber + 1
		_, err := updateBundle(tx, newBundle, nil)
		if err != nil {
			return false, fmt.Errorf("unable to write new bundle: %w", err)
		}
	}

	return changed, nil
}

func taintX509CA(tx *gorm.DB, trustDomainID string, subjectKeyIDToTaint string) error {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return err
	}

	found := false
	for _, eachRootCA := range bundle.RootCas {
		x509CA, err := x509.ParseCertificate(eachRootCA.DerBytes)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse rootCA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(x509CA.SubjectKeyId)
		if subjectKeyIDToTaint != caSubjectKeyID {
			continue
		}

		if eachRootCA.TaintedKey {
			return status.Errorf(codes.InvalidArgument, "root CA is already tainted")
		}

		found = true
		eachRootCA.TaintedKey = true
	}

	if !found {
		return status.Error(codes.NotFound, "no ca found with provided subject key ID")
	}

	bundle.SequenceNumber++

	_, err = updateBundle(tx, bundle, nil)
	if err != nil {
		return err
	}

	return nil
}

func revokeX509CA(tx *gorm.DB, trustDomainID string, subjectKeyIDToRevoke string) error {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return err
	}

	keyFound := false
	var rootCAs []*common.Certificate
	for _, ca := range bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse root CA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		if subjectKeyIDToRevoke == caSubjectKeyID {
			if !ca.TaintedKey {
				return status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted root CA")
			}
			keyFound = true
			continue
		}

		rootCAs = append(rootCAs, ca)
	}

	if !keyFound {
		return status.Error(codes.NotFound, "no root CA found with provided subject key ID")
	}

	bundle.RootCas = rootCAs
	bundle.SequenceNumber++

	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return status.Errorf(codes.Internal, "failed to update bundle: %v", err)
	}

	return nil
}

func taintJWTKey(tx *gorm.DB, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return nil, err
	}

	var taintedKey *common.PublicKey
	for _, jwtKey := range bundle.JwtSigningKeys {
		if jwtKey.Kid != authorityID {
			continue
		}

		if jwtKey.TaintedKey {
			return nil, status.Error(codes.InvalidArgument, "key is already tainted")
		}

		// Check if a JWT Key with the provided keyID was already
		// tainted in this loop. This is purely defensive since we do not
		// allow to have repeated key IDs.
		if taintedKey != nil {
			return nil, status.Error(codes.Internal, "another JWT Key found with the same KeyID")
		}
		taintedKey = jwtKey
		jwtKey.TaintedKey = true
	}

	if taintedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	bundle.SequenceNumber++
	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return nil, err
	}

	return taintedKey, nil
}

func revokeJWTKey(tx *gorm.DB, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return nil, err
	}

	var publicKeys []*common.PublicKey
	var revokedKey *common.PublicKey
	for _, key := range bundle.JwtSigningKeys {
		if key.Kid == authorityID {
			// Check if a JWT Key with the provided keyID was already
			// found in this loop. This is purely defensive since we do not
			// allow to have repeated key IDs.
			if revokedKey != nil {
				return nil, status.Error(codes.Internal, "another key found with the same KeyID")
			}

			if !key.TaintedKey {
				return nil, status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted key")
			}

			revokedKey = key
			continue
		}
		publicKeys = append(publicKeys, key)
	}
	bundle.JwtSigningKeys = publicKeys

	if revokedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	bundle.SequenceNumber++
	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return nil, err
	}

	return revokedKey, nil
}

func getBundle(tx *gorm.DB, trustDomainID string) (*common.Bundle, error) {
	model := &Bundle{}
	if err := tx.Find(model, "trust_domain = ?", trustDomainID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal bundle: %v", err)
	}

	return bundle, nil
}

func createAttestedNode(tx *gorm.DB, node *common.AttestedNode) (*common.AttestedNode, error) {
	model := AttestedNode{
		SpiffeID:        node.SpiffeId,
		DataType:        node.AttestationDataType,
		SerialNumber:    node.CertSerialNumber,
		ExpiresAt:       time.Unix(node.CertNotAfter, 0),
		NewSerialNumber: node.NewCertSerialNumber,
		NewExpiresAt:    nullableUnixTimeToDBTime(node.NewCertNotAfter),
		CanReattest:     node.CanReattest,
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToAttestedNode(model), nil
}

func fetchAttestedNode(tx *gorm.DB, spiffeID string) (*common.AttestedNode, error) {
	var model AttestedNode
	err := tx.Find(&model, "spiffe_id = ?", spiffeID).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}
	return modelToAttestedNode(model), nil
}

func countAttestedNodes(tx *gorm.DB) (int32, error) {
	var count int
	if err := tx.Model(&AttestedNode{}).Count(&count).Error; err != nil {
		return 0, sqlError.Wrap(err)
	}

	return int32(count), nil
}

func countAttestedNodesHasFilters(req *datastore.CountAttestedNodesRequest) bool {
	if req.ByAttestationType != "" || req.ByBanned != nil || !req.ByExpiresBefore.IsZero() {
		return true
	}
	if req.BySelectorMatch != nil || !req.FetchSelectors || req.ByCanReattest != nil {
		return true
	}
	return false
}

func listAttestedNodes(ctx context.Context, db *sqlDB, log logrus.FieldLogger, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}

	for {
		resp, err := listAttestedNodesOnce(ctx, db, req)
		if err != nil {
			return nil, err
		}

		if req.BySelectorMatch == nil || len(resp.Nodes) == 0 {
			return resp, nil
		}

		switch req.BySelectorMatch.Match {
		case datastore.Exact, datastore.Subset:
			resp.Nodes = filterNodesBySelectorSet(resp.Nodes, req.BySelectorMatch.Selectors)
		default:
		}

		// Now that we've filtered the nodes based on selectors, prune off
		// selectors from the response if they were not requested.
		if !req.FetchSelectors {
			for _, node := range resp.Nodes {
				node.Selectors = nil
			}
		}

		if len(resp.Nodes) > 0 || resp.Pagination == nil || len(resp.Pagination.Token) == 0 {
			return resp, nil
		}

		if resp.Pagination.Token == req.Pagination.Token {
			// This check is purely defensive. Assuming the pagination code is
			// correct, a request with a given token should never yield that
			// same token. Just in case, we don't want the server to loop
			// indefinitely.
			log.Warn("Filtered attested node pagination would recurse. Please report this bug.")
			resp.Pagination.Token = ""
			return resp, nil
		}

		req.Pagination = resp.Pagination
	}
}

func countAttestedNodesWithFilters(ctx context.Context, db *sqlDB, _ logrus.FieldLogger, req *datastore.CountAttestedNodesRequest) (int32, error) {
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) == 0 {
		return -1, status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}

	var val int32
	listReq := &datastore.ListAttestedNodesRequest{
		ByAttestationType: req.ByAttestationType,
		ByBanned:          req.ByBanned,
		ByExpiresBefore:   req.ByExpiresBefore,
		BySelectorMatch:   req.BySelectorMatch,
		FetchSelectors:    req.FetchSelectors,
		ByCanReattest:     req.ByCanReattest,
		Pagination: &datastore.Pagination{
			Token:    "",
			PageSize: 1000,
		},
	}
	for {
		resp, err := listAttestedNodesOnce(ctx, db, listReq)
		if err != nil {
			return -1, err
		}

		if len(resp.Nodes) == 0 {
			return val, nil
		}

		if req.BySelectorMatch != nil {
			switch req.BySelectorMatch.Match {
			case datastore.Exact, datastore.Subset:
				resp.Nodes = filterNodesBySelectorSet(resp.Nodes, req.BySelectorMatch.Selectors)
			default:
			}
		}

		val += int32(len(resp.Nodes))

		listReq.Pagination = resp.Pagination
	}
}

func createAttestedNodeEvent(tx *gorm.DB, event *datastore.AttestedNodeEvent) error {
	if err := tx.Create(&AttestedNodeEvent{
		Model: Model{
			ID: event.EventID,
		},
		SpiffeID: event.SpiffeID,
	}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func listAttestedNodeEvents(tx *gorm.DB, req *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	var events []AttestedNodeEvent

	if req.GreaterThanEventID != 0 || req.LessThanEventID != 0 {
		query, id, err := buildListEventsQueryString(req.GreaterThanEventID, req.LessThanEventID)
		if err != nil {
			return nil, sqlError.Wrap(err)
		}

		if err := tx.Find(&events, query.String(), id).Order("id asc").Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	} else {
		if err := tx.Find(&events).Order("id asc").Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	resp := &datastore.ListAttestedNodeEventsResponse{
		Events: make([]datastore.AttestedNodeEvent, len(events)),
	}
	for i, event := range events {
		resp.Events[i].EventID = event.ID
		resp.Events[i].SpiffeID = event.SpiffeID
	}

	return resp, nil
}

func pruneAttestedNodeEvents(tx *gorm.DB, olderThan time.Duration) error {
	if err := tx.Where("created_at < ?", time.Now().Add(-olderThan)).Delete(&AttestedNodeEvent{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func fetchAttestedNodeEvent(db *sqlDB, eventID uint) (*datastore.AttestedNodeEvent, error) {
	event := AttestedNodeEvent{}
	if err := db.Find(&event, "id = ?", eventID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.AttestedNodeEvent{
		EventID:  event.ID,
		SpiffeID: event.SpiffeID,
	}, nil
}

func deleteAttestedNodeEvent(tx *gorm.DB, eventID uint) error {
	if err := tx.Delete(&AttestedNodeEvent{
		Model: Model{
			ID: eventID,
		},
	}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

// filterNodesBySelectorSet filters nodes based on provided selectors
func filterNodesBySelectorSet(nodes []*common.AttestedNode, selectors []*common.Selector) []*common.AttestedNode {
	type selectorKey struct {
		Type  string
		Value string
	}
	set := make(map[selectorKey]struct{}, len(selectors))
	for _, s := range selectors {
		set[selectorKey{Type: s.Type, Value: s.Value}] = struct{}{}
	}

	isSubset := func(ss []*common.Selector) bool {
		for _, s := range ss {
			if _, ok := set[selectorKey{Type: s.Type, Value: s.Value}]; !ok {
				return false
			}
		}
		return true
	}

	filtered := make([]*common.AttestedNode, 0, len(nodes))
	for _, node := range nodes {
		if isSubset(node.Selectors) {
			filtered = append(filtered, node)
		}
	}

	return filtered
}

func listAttestedNodesOnce(ctx context.Context, db *sqlDB, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	query, args, err := buildListAttestedNodesQuery(db.databaseType, db.supportsCTE, req)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	nodes := make([]*common.AttestedNode, 0, calculateResultPreallocation(req.Pagination))
	pushNode := func(node *common.AttestedNode) {
		if node != nil && node.SpiffeId != "" {
			nodes = append(nodes, node)
		}
	}

	var lastEID uint64
	var node *common.AttestedNode
	for rows.Next() {
		var r nodeRow
		if err := scanNodeRow(rows, &r); err != nil {
			return nil, err
		}

		if node == nil || lastEID != r.EId {
			lastEID = r.EId
			pushNode(node)
			node = new(common.AttestedNode)
		}

		if err := fillNodeFromRow(node, &r); err != nil {
			return nil, err
		}
	}
	pushNode(node)

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.ListAttestedNodesResponse{
		Nodes: nodes,
	}

	if req.Pagination != nil {
		resp.Pagination = &datastore.Pagination{
			PageSize: req.Pagination.PageSize,
		}
		if len(resp.Nodes) > 0 {
			resp.Pagination.Token = strconv.FormatUint(lastEID, 10)
		}
	}
	return resp, nil
}

func buildListAttestedNodesQuery(dbType string, supportsCTE bool, req *datastore.ListAttestedNodesRequest) (string, []any, error) {
	switch {
	case isSQLiteDbType(dbType):
		return buildListAttestedNodesQueryCTE(req, dbType)
	case isPostgresDbType(dbType):
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		query, args, err := buildListAttestedNodesQueryCTE(req, dbType)
		if err != nil {
			return query, args, err
		}
		return postgreSQLRebind(query), args, nil
	case isMySQLDbType(dbType):
		if supportsCTE {
			return buildListAttestedNodesQueryCTE(req, dbType)
		}
		return buildListAttestedNodesQueryMySQL(req)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildListAttestedNodesQueryCTE(req *datastore.ListAttestedNodesRequest, dbType string) (string, []any, error) {
	builder := new(strings.Builder)
	var args []any

	// Selectors will be fetched only when `FetchSelectors` or BySelectorMatch are in request
	fetchSelectors := req.FetchSelectors || req.BySelectorMatch != nil

	// Creates filtered nodes, `true` is added to simplify code, all filters will start with `AND`
	builder.WriteString("\nWITH filtered_nodes AS (\n")
	builder.WriteString("\tSELECT * FROM attested_node_entries WHERE true\n")

	// Filter by pagination token
	if req.Pagination != nil && req.Pagination.Token != "" {
		token, err := strconv.ParseUint(req.Pagination.Token, 10, 32)
		if err != nil {
			return "", nil, status.Errorf(codes.InvalidArgument, "could not parse token '%v'", req.Pagination.Token)
		}
		builder.WriteString("\t\tAND id > ?")
		args = append(args, token)
	}

	// Filter by expiration
	if !req.ByExpiresBefore.IsZero() {
		builder.WriteString("\t\tAND expires_at < ?\n")
		args = append(args, req.ByExpiresBefore)
	}

	// Filter by Attestation type
	if req.ByAttestationType != "" {
		builder.WriteString("\t\tAND data_type = ?\n")
		args = append(args, req.ByAttestationType)
	}
	// Filter by banned, an Attestation Node is banned when serial number is empty.
	// This filter allows 3 outputs:
	// - nil:  returns all
	// - true: returns banned entries
	// - false: returns no banned entries
	if req.ByBanned != nil {
		if *req.ByBanned {
			builder.WriteString("\t\tAND serial_number = ''\n")
		} else {
			builder.WriteString("\t\tAND serial_number <> ''\n")
		}
	}
	// Filter by canReattest,
	// This filter allows 3 outputs:
	//  - nil:  returns all
	// - true: returns nodes with canReattest=true
	// - false: returns nodes with canReattest=false
	if req.ByCanReattest != nil {
		if *req.ByCanReattest {
			builder.WriteString("\t\tAND can_reattest = true\n")
		} else {
			builder.WriteString("\t\tAND can_reattest = false\n")
		}
	}

	builder.WriteString(")")
	// Fetch all selectors from filtered entries
	if fetchSelectors {
		builder.WriteString(`, filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)
`)
	}

	// Add expected fields
	builder.WriteString(`
SELECT
	id AS e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	can_reattest,`)

	// Add "optional" fields for selectors
	if fetchSelectors {
		builder.WriteString(`
	selector_type,
	selector_value 
	  `)
	} else {
		builder.WriteString(`
	NULL AS selector_type,
	NULL AS selector_value`)
	}

	// Choose what table will be used
	fromQuery := "FROM filtered_nodes"
	if fetchSelectors {
		fromQuery = "FROM filtered_nodes_and_selectors"
	}

	builder.WriteString("\n")
	builder.WriteString(fromQuery)
	builder.WriteString("\nWHERE id IN (\n")

	// MySQL requires a subquery in order to apply pagination
	if req.Pagination != nil && isMySQLDbType(dbType) {
		builder.WriteString("\tSELECT id FROM (\n")
	}

	// Add filter by selectors
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) > 0 {
		// Select IDs, that will be used to fetch "paged" entrieSelect IDs, that will be used to fetch "paged" entries
		builder.WriteString("\tSELECT DISTINCT id FROM (\n")

		query := "SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?"

		switch req.BySelectorMatch.Match {
		case datastore.Subset, datastore.MatchAny:
			// Subset needs a union, so we need to group them and add the group
			// as a child to the root
			for i := range req.BySelectorMatch.Selectors {
				builder.WriteString("\t\t")
				builder.WriteString(query)
				if i < (len(req.BySelectorMatch.Selectors) - 1) {
					builder.WriteString("\n\t\tUNION\n")
				}
			}
		case datastore.Exact, datastore.Superset:
			for i := range req.BySelectorMatch.Selectors {
				switch {
				// MySQL does not support INTERSECT, so use INNER JOIN instead
				case isMySQLDbType(dbType):
					if len(req.BySelectorMatch.Selectors) > 1 {
						builder.WriteString("\t\t(")
					}
					builder.WriteString(query)
					if len(req.BySelectorMatch.Selectors) > 1 {
						builder.WriteString(fmt.Sprintf(") c_%d\n", i))
					}
					// First subquery does not need USING(ID)
					if i > 0 {
						builder.WriteString("\t\tUSING(id)\n")
					}
					// Last query does not need INNER JOIN
					if i < (len(req.BySelectorMatch.Selectors) - 1) {
						builder.WriteString("\t\tINNER JOIN\n")
					}
				default:
					builder.WriteString("\t\t")
					builder.WriteString(query)
					if i < (len(req.BySelectorMatch.Selectors) - 1) {
						builder.WriteString("\n\t\tINTERSECT\n")
					}
				}
			}
		default:
			return "", nil, errs.New("unhandled match behavior %q", req.BySelectorMatch.Match)
		}

		// Add all selectors as arguments
		for _, selector := range req.BySelectorMatch.Selectors {
			args = append(args, selector.Type, selector.Value)
		}

		builder.WriteString("\n\t)")
	} else {
		// Prevent duplicate IDs when fetching selectors
		if fetchSelectors {
			builder.WriteString("\t\tSELECT DISTINCT id ")
		} else {
			builder.WriteString("\t\tSELECT id ")
		}
		builder.WriteString("\n\t\t")
		builder.WriteString(fromQuery)
	}

	if isPostgresDbType(dbType) ||
		(req.BySelectorMatch != nil &&
			(req.BySelectorMatch.Match == datastore.Subset || req.BySelectorMatch.Match == datastore.MatchAny || len(req.BySelectorMatch.Selectors) == 1)) {
		builder.WriteString(" AS result_nodes")
	}

	if req.Pagination != nil {
		builder.WriteString(" ORDER BY id ASC LIMIT ")
		builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))

		// Add workaround for limit
		if isMySQLDbType(dbType) {
			builder.WriteString("\n\t) workaround_for_mysql_subquery_limit")
		}
	}

	builder.WriteString("\n) ORDER BY id ASC\n")
	return builder.String(), args, nil
}

func buildListAttestedNodesQueryMySQL(req *datastore.ListAttestedNodesRequest) (string, []any, error) {
	builder := new(strings.Builder)
	var args []any

	// Selectors will be fetched only when `FetchSelectors` or `BySelectorMatch` are in request
	fetchSelectors := req.FetchSelectors || req.BySelectorMatch != nil

	// Add expected fields
	builder.WriteString(`
SELECT 
	N.id AS e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	N.can_reattest,`)
	// Add "optional" fields for selectors
	if fetchSelectors {
		builder.WriteString(`
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
`)
	} else {
		builder.WriteString(`
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
`)
	}

	writeFilter := func() error {
		builder.WriteString("WHERE true")

		// Filter by pagination token
		if req.Pagination != nil && req.Pagination.Token != "" {
			token, err := strconv.ParseUint(req.Pagination.Token, 10, 32)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "could not parse token '%v'", req.Pagination.Token)
			}
			builder.WriteString(" AND N.id > ?")
			args = append(args, token)
		}

		// Filter by expiration
		if !req.ByExpiresBefore.IsZero() {
			builder.WriteString(" AND N.expires_at < ?")
			args = append(args, req.ByExpiresBefore)
		}

		// Filter by Attestation type
		if req.ByAttestationType != "" {
			builder.WriteString(" AND N.data_type = ?")
			args = append(args, req.ByAttestationType)
		}

		// Filter by banned, an Attestation Node is banned when serial number is empty.
		// This filter allows 3 outputs:
		// - nil:  returns all
		// - true: returns banned entries
		// - false: returns no banned entries
		if req.ByBanned != nil {
			if *req.ByBanned {
				builder.WriteString(" AND N.serial_number = ''")
			} else {
				builder.WriteString(" AND N.serial_number <> ''")
			}
		}

		// Filter by CanReattest. This is similar to ByBanned
		if req.ByCanReattest != nil {
			if *req.ByCanReattest {
				builder.WriteString("\t\tAND can_reattest = true\n")
			} else {
				builder.WriteString("\t\tAND can_reattest = false\n")
			}
		}
		return nil
	}

	// Add filter by selectors
	if fetchSelectors {
		builder.WriteString("WHERE N.id IN (\n")
		if req.Pagination != nil {
			builder.WriteString("\tSELECT id FROM (\n")
		}
		builder.WriteString("\t\tSELECT DISTINCT id FROM (\n")

		builder.WriteString("\t\t\t(SELECT N.id, N.spiffe_id FROM attested_node_entries N ")
		if err := writeFilter(); err != nil {
			return "", nil, err
		}
		builder.WriteString(") c_0\n")

		if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) > 0 {
			query := "SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?"

			switch req.BySelectorMatch.Match {
			case datastore.Subset, datastore.MatchAny:
				builder.WriteString("\t\t\tINNER JOIN\n")
				builder.WriteString("\t\t\t(SELECT spiffe_id FROM (\n")

				// subset needs a union, so we need to group them and add the group
				// as a child to the root.
				for i := range req.BySelectorMatch.Selectors {
					builder.WriteString("\t\t\t\t")
					builder.WriteString(query)
					if i < (len(req.BySelectorMatch.Selectors) - 1) {
						builder.WriteString("\n\t\t\t\tUNION\n")
					}
				}

				builder.WriteString("\t\t\t) s_1) c_2\n")
				builder.WriteString("\t\t\tUSING(spiffe_id)\n")
			case datastore.Exact, datastore.Superset:
				for i := range req.BySelectorMatch.Selectors {
					builder.WriteString("\t\t\tINNER JOIN\n")
					builder.WriteString("\t\t\t(")
					builder.WriteString(query)
					builder.WriteString(fmt.Sprintf(") c_%d\n", i+1))
					builder.WriteString("\t\t\tUSING(spiffe_id)\n")
				}
			default:
				return "", nil, errs.New("unhandled match behavior %q", req.BySelectorMatch.Match)
			}

			for _, selector := range req.BySelectorMatch.Selectors {
				args = append(args, selector.Type, selector.Value)
			}
		}
		if req.Pagination != nil {
			builder.WriteString("\t\t) ORDER BY id ASC LIMIT ")
			builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))
			builder.WriteString("\n")

			builder.WriteString("\t) workaround_for_mysql_subquery_limit\n")
		} else {
			builder.WriteString("\t)\n")
		}
		builder.WriteString(") ORDER BY e_id, S.id\n")
	} else {
		if err := writeFilter(); err != nil {
			return "", nil, err
		}
		if req.Pagination != nil {
			builder.WriteString(" ORDER BY N.id ASC LIMIT ")
			builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))
		}
		builder.WriteString("\n")
	}

	return builder.String(), args, nil
}

func updateAttestedNode(tx *gorm.DB, n *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	var model AttestedNode
	if err := tx.Find(&model, "spiffe_id = ?", n.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if mask == nil {
		mask = protoutil.AllTrueCommonAgentMask
	}

	updates := make(map[string]any)
	if mask.CertNotAfter {
		updates["expires_at"] = time.Unix(n.CertNotAfter, 0)
	}
	if mask.CertSerialNumber {
		updates["serial_number"] = n.CertSerialNumber
	}
	if mask.NewCertNotAfter {
		updates["new_expires_at"] = nullableUnixTimeToDBTime(n.NewCertNotAfter)
	}
	if mask.NewCertSerialNumber {
		updates["new_serial_number"] = n.NewCertSerialNumber
	}
	if mask.CanReattest {
		updates["can_reattest"] = n.CanReattest
	}
	if err := tx.Model(&model).Updates(updates).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToAttestedNode(model), nil
}

func deleteAttestedNodeAndSelectors(tx *gorm.DB, spiffeID string) (*common.AttestedNode, error) {
	var (
		nodeModel         AttestedNode
		nodeSelectorModel NodeSelector
	)

	// batch delete all associated node selectors
	if err := tx.Where("spiffe_id = ?", spiffeID).Delete(&nodeSelectorModel).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Find(&nodeModel, "spiffe_id = ?", spiffeID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&nodeModel).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToAttestedNode(nodeModel), nil
}

func setNodeSelectors(tx *gorm.DB, spiffeID string, selectors []*common.Selector) error {
	// Previously the deletion of the previous set of node selectors was
	// implemented via query like DELETE FROM node_resolver_map_entries WHERE
	// spiffe_id = ?, but unfortunately this triggered some pessimistic gap
	// locks on the index even when there were no rows matching the WHERE
	// clause (i.e. rows for that spiffe_id). The gap locks caused MySQL
	// deadlocks when SetNodeSelectors was being called concurrently. Changing
	// the transaction isolation level fixed the deadlocks but only when there
	// were no existing rows; the deadlocks still occurred when existing rows
	// existed (i.e. re-attestation). Instead, gather all of the IDs to be
	// deleted and delete them from separate queries, which does not trigger
	// gap locks on the index.
	var ids []int64
	if err := tx.Model(&NodeSelector{}).Where("spiffe_id = ?", spiffeID).Pluck("id", &ids).Error; err != nil {
		return sqlError.Wrap(err)
	}
	if len(ids) > 0 {
		if err := tx.Where("id IN (?)", ids).Delete(&NodeSelector{}).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	for _, selector := range selectors {
		model := &NodeSelector{
			SpiffeID: spiffeID,
			Type:     selector.Type,
			Value:    selector.Value,
		}
		if err := tx.Create(model).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	return nil
}

func getNodeSelectors(ctx context.Context, db *sqlDB, spiffeID string) ([]*common.Selector, error) {
	query := maybeRebind(db.databaseType, "SELECT type, value FROM node_resolver_map_entries WHERE spiffe_id=? ORDER BY id")
	rows, err := db.QueryContext(ctx, query, spiffeID)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	var selectors []*common.Selector
	for rows.Next() {
		selector := new(common.Selector)
		if err := rows.Scan(&selector.Type, &selector.Value); err != nil {
			return nil, sqlError.Wrap(err)
		}
		selectors = append(selectors, selector)
	}

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	return selectors, nil
}

func listNodeSelectors(ctx context.Context, db *sqlDB, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	rawQuery, args := buildListNodeSelectorsQuery(req)
	query := maybeRebind(db.databaseType, rawQuery)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	resp := &datastore.ListNodeSelectorsResponse{
		Selectors: make(map[string][]*common.Selector),
	}

	var currentID string
	selectors := make([]*common.Selector, 0, 64)

	push := func(spiffeID string, selector *common.Selector) {
		switch {
		case currentID == "":
			currentID = spiffeID
		case spiffeID != currentID:
			resp.Selectors[currentID] = append(resp.Selectors[currentID], selectors...)
			currentID = spiffeID
			selectors = selectors[:0]
		}
		selectors = append(selectors, selector)
	}

	for rows.Next() {
		var nsRow nodeSelectorRow
		if err := scanNodeSelectorRow(rows, &nsRow); err != nil {
			return nil, err
		}

		var spiffeID string
		if nsRow.SpiffeID.Valid {
			spiffeID = nsRow.SpiffeID.String
		}

		selector := new(common.Selector)
		fillNodeSelectorFromRow(selector, &nsRow)
		push(spiffeID, selector)
	}

	push("", nil)

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	return resp, nil
}

func buildListNodeSelectorsQuery(req *datastore.ListNodeSelectorsRequest) (query string, args []any) {
	var sb strings.Builder
	sb.WriteString("SELECT nre.spiffe_id, nre.type, nre.value FROM node_resolver_map_entries nre")
	if !req.ValidAt.IsZero() {
		sb.WriteString(" INNER JOIN attested_node_entries ane ON nre.spiffe_id=ane.spiffe_id WHERE ane.expires_at > ?")
		args = append(args, req.ValidAt)
	}

	// This ordering is required to make listNodeSelectors efficient but not
	// needed for correctness. Since the query can be wholly satisfied using
	// the node_resolver_map_entries unique index over (spiffe_id,type,value)
	// it is unlikely to impact database performance as that index is already
	// ordered primarily by spiffe_id.
	sb.WriteString(" ORDER BY nre.spiffe_id ASC")

	return sb.String(), args
}

func createRegistrationEntry(tx *gorm.DB, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	entryID, err := createOrReturnEntryID(entry)
	if err != nil {
		return nil, err
	}

	newRegisteredEntry := RegisteredEntry{
		EntryID:    entryID,
		SpiffeID:   entry.SpiffeId,
		ParentID:   entry.ParentId,
		TTL:        entry.X509SvidTtl,
		Admin:      entry.Admin,
		Downstream: entry.Downstream,
		Expiry:     entry.EntryExpiry,
		StoreSvid:  entry.StoreSvid,
		JWTSvidTTL: entry.JwtSvidTtl,
		Hint:       entry.Hint,
	}

	if err := tx.Create(&newRegisteredEntry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	federatesWith, err := makeFederatesWith(tx, entry.FederatesWith)
	if err != nil {
		return nil, err
	}

	if err := tx.Model(&newRegisteredEntry).Association("FederatesWith").Append(federatesWith).Error; err != nil {
		return nil, err
	}

	for _, registeredSelector := range entry.Selectors {
		newSelector := Selector{
			RegisteredEntryID: newRegisteredEntry.ID,
			Type:              registeredSelector.Type,
			Value:             registeredSelector.Value,
		}

		if err := tx.Create(&newSelector).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	for _, registeredDNS := range entry.DnsNames {
		newDNS := DNSName{
			RegisteredEntryID: newRegisteredEntry.ID,
			Value:             registeredDNS,
		}

		if err := tx.Create(&newDNS).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	registrationEntry, err := modelToEntry(tx, newRegisteredEntry)
	if err != nil {
		return nil, err
	}

	return registrationEntry, nil
}

func fetchRegistrationEntry(ctx context.Context, db *sqlDB, entryID string) (*common.RegistrationEntry, error) {
	query, args, err := buildFetchRegistrationEntryQuery(db.databaseType, db.supportsCTE, entryID)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	var entry *common.RegistrationEntry
	for rows.Next() {
		var r entryRow
		if err := scanEntryRow(rows, &r); err != nil {
			return nil, err
		}

		if entry == nil {
			entry = new(common.RegistrationEntry)
		}
		if err := fillEntryFromRow(entry, &r); err != nil {
			return nil, err
		}
	}

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	return entry, nil
}

func buildFetchRegistrationEntryQuery(dbType string, supportsCTE bool, entryID string) (string, []any, error) {
	switch {
	case isSQLiteDbType(dbType):
		// The SQLite3 queries unconditionally leverage CTE since the
		// embedded version of SQLite3 supports CTE.
		return buildFetchRegistrationEntryQuerySQLite3(entryID)
	case isPostgresDbType(dbType):
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		return buildFetchRegistrationEntryQueryPostgreSQL(entryID)
	case isMySQLDbType(dbType):
		if supportsCTE {
			return buildFetchRegistrationEntryQueryMySQLCTE(entryID)
		}
		return buildFetchRegistrationEntryQueryMySQL(entryID)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildFetchRegistrationEntryQuerySQLite3(entryID string) (string, []any, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []any{entryID}, nil
}

func buildFetchRegistrationEntryQueryPostgreSQL(entryID string) (string, []any, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = $1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []any{entryID}, nil
}

func buildFetchRegistrationEntryQueryMySQL(entryID string) (string, []any, error) {
	const query = `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	E.store_svid,
	E.hint,
	E.created_at,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number,
	E.jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.entry_id = ?
ORDER BY selector_id, dns_name_id
;`
	return query, []any{entryID}, nil
}

func buildFetchRegistrationEntryQueryMySQLCTE(entryID string) (string, []any, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []any{entryID}, nil
}

func listRegistrationEntries(ctx context.Context, db *sqlDB, log logrus.FieldLogger, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}

	// Exact/subset selector matching requires filtering out all registration
	// entries returned by the query whose selectors are not fully represented
	// in the request selectors. For this reason, it's possible that a paged
	// query returns rows that are completely filtered out. If that happens,
	// keep querying until a page gets at least one result.
	for {
		resp, err := listRegistrationEntriesOnce(ctx, db.raw, db.databaseType, db.supportsCTE, req)
		if err != nil {
			return nil, err
		}

		if req.BySelectors == nil || len(resp.Entries) == 0 {
			return resp, nil
		}

		switch req.BySelectors.Match {
		case datastore.Exact, datastore.Subset:
			resp.Entries = filterEntriesBySelectorSet(resp.Entries, req.BySelectors.Selectors)
		default:
		}

		if len(resp.Entries) > 0 || resp.Pagination == nil || len(resp.Pagination.Token) == 0 {
			return resp, nil
		}

		if resp.Pagination.Token == req.Pagination.Token {
			// This check is purely defensive. Assuming the pagination code is
			// correct, a request with a given token should never yield that
			// same token. Just in case, we don't want the server to loop
			// indefinitely.
			log.Warn("Filtered registration entry pagination would recurse. Please report this bug.")
			resp.Pagination.Token = ""
			return resp, nil
		}

		req.Pagination = resp.Pagination
	}
}

func filterEntriesBySelectorSet(entries []*common.RegistrationEntry, selectors []*common.Selector) []*common.RegistrationEntry {
	// Nothing to filter
	if len(entries) == 0 {
		return entries
	}
	type selectorKey struct {
		Type  string
		Value string
	}
	set := make(map[selectorKey]struct{}, len(selectors))
	for _, s := range selectors {
		set[selectorKey{Type: s.Type, Value: s.Value}] = struct{}{}
	}

	isSubset := func(ss []*common.Selector) bool {
		for _, s := range ss {
			if _, ok := set[selectorKey{Type: s.Type, Value: s.Value}]; !ok {
				return false
			}
		}
		return true
	}

	filtered := make([]*common.RegistrationEntry, 0, len(entries))
	for _, entry := range entries {
		if isSubset(entry.Selectors) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

type queryContext interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listRegistrationEntriesOnce(ctx context.Context, db queryContext, databaseType string, supportsCTE bool, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	query, args, err := buildListRegistrationEntriesQuery(databaseType, supportsCTE, req)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()
	entries := make([]*common.RegistrationEntry, 0, calculateResultPreallocation(req.Pagination))
	pushEntry := func(entry *common.RegistrationEntry) {
		// Due to previous bugs (i.e. #1191), there can be cruft rows related
		// to a deleted registration entries that are fetched with the list
		// query. To avoid hydrating partial entries, append only entries that
		// have data from the registered_entries table (i.e. those with an
		// entry id).
		if entry != nil && entry.EntryId != "" {
			entries = append(entries, entry)
		}
	}

	var lastEID uint64
	var entry *common.RegistrationEntry
	for rows.Next() {
		var r entryRow
		if err := scanEntryRow(rows, &r); err != nil {
			return nil, err
		}

		if entry == nil || lastEID != r.EId {
			lastEID = r.EId
			pushEntry(entry)
			entry = new(common.RegistrationEntry)
		}

		if err := fillEntryFromRow(entry, &r); err != nil {
			return nil, err
		}
	}
	pushEntry(entry)

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.ListRegistrationEntriesResponse{
		Entries: entries,
	}

	if req.Pagination != nil {
		resp.Pagination = &datastore.Pagination{
			PageSize: req.Pagination.PageSize,
		}
		if len(resp.Entries) > 0 {
			resp.Pagination.Token = strconv.FormatUint(lastEID, 10)
		}
	}

	return resp, nil
}

func buildListRegistrationEntriesQuery(dbType string, supportsCTE bool, req *datastore.ListRegistrationEntriesRequest) (string, []any, error) {
	switch {
	case isSQLiteDbType(dbType):
		// The SQLite3 queries unconditionally leverage CTE since the
		// embedded version of SQLite3 supports CTE.
		return buildListRegistrationEntriesQuerySQLite3(req)
	case isPostgresDbType(dbType):
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		return buildListRegistrationEntriesQueryPostgreSQL(req)
	case isMySQLDbType(dbType):
		if supportsCTE {
			return buildListRegistrationEntriesQueryMySQLCTE(req)
		}
		return buildListRegistrationEntriesQueryMySQL(req)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildListRegistrationEntriesQuerySQLite3(req *datastore.ListRegistrationEntriesRequest) (string, []any, error) {
	builder := new(strings.Builder)
	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, SQLite, req)
	downstream := false
	if req.ByDownstream != nil {
		downstream = *req.ByDownstream
	}

	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
`)

	if filtered {
		builder.WriteString("WHERE id IN (SELECT e_id FROM listing)\n")
	}
	if downstream {
		if !filtered {
			builder.WriteString("\t\tWHERE downstream = true\n")
		} else {
			builder.WriteString("\t\tAND downstream = true\n")
		}
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return builder.String(), args, nil
}

func buildListRegistrationEntriesQueryPostgreSQL(req *datastore.ListRegistrationEntriesRequest) (string, []any, error) {
	builder := new(strings.Builder)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, PostgreSQL, req)
	downstream := false
	if req.ByDownstream != nil {
		downstream = *req.ByDownstream
	}

	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT e_id FROM listing)\n")
	}
	if downstream {
		if !filtered {
			builder.WriteString("\t\tWHERE downstream = true\n")
		} else {
			builder.WriteString("\t\tAND downstream = true\n")
		}
	}
	builder.WriteString(`
UNION ALL

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION ALL

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION ALL

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return postgreSQLRebind(builder.String()), args, nil
}

func maybeRebind(dbType, query string) string {
	if isPostgresDbType(dbType) {
		return postgreSQLRebind(query)
	}
	return query
}

func postgreSQLRebind(s string) string {
	return bindVarsFn(func(n int) string {
		return "$" + strconv.Itoa(n)
	}, s)
}

func buildListRegistrationEntriesQueryMySQL(req *datastore.ListRegistrationEntriesRequest) (string, []any, error) {
	builder := new(strings.Builder)
	builder.WriteString(`
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	E.store_svid,
	E.hint,
	E.created_at,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number,
	E.jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
`)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("WHERE E.id IN (\n", builder, MySQL, req)
	downstream := false
	if req.ByDownstream != nil {
		downstream = *req.ByDownstream
	}

	if err != nil {
		return "", nil, err
	}

	if filtered {
		builder.WriteString(")")
	}
	if downstream {
		if !filtered {
			builder.WriteString("\t\tWHERE downstream = true\n")
		} else {
			builder.WriteString("\t\tAND downstream = true\n")
		}
	}
	builder.WriteString("\nORDER BY e_id, selector_id, dns_name_id\n;")

	return builder.String(), args, nil
}

func buildListRegistrationEntriesQueryMySQLCTE(req *datastore.ListRegistrationEntriesRequest) (string, []any, error) {
	builder := new(strings.Builder)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, MySQL, req)
	downstream := false
	if req.ByDownstream != nil {
		downstream = *req.ByDownstream
	}

	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	store_svid,
	hint,
	created_at,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number,
	jwt_svid_ttl AS reg_jwt_svid_ttl
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT e_id FROM listing)\n")
	}
	if downstream {
		if !filtered {
			builder.WriteString("\t\tWHERE downstream = true\n")
		} else {
			builder.WriteString("\t\tAND downstream = true\n")
		}
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT e_id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return builder.String(), args, nil
}

// Count Registration Entries
func countRegistrationEntries(ctx context.Context, db *sqlDB, _ logrus.FieldLogger, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return 0, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}

	var val int32
	listReq := &datastore.ListRegistrationEntriesRequest{
		DataConsistency: req.DataConsistency,
		ByParentID:      req.ByParentID,
		BySelectors:     req.BySelectors,
		BySpiffeID:      req.BySpiffeID,
		ByFederatesWith: req.ByFederatesWith,
		ByHint:          req.ByHint,
		ByDownstream:    req.ByDownstream,
		Pagination: &datastore.Pagination{
			Token:    "",
			PageSize: 1000,
		},
	}

	for {
		resp, err := listRegistrationEntriesOnce(ctx, db.raw, db.databaseType, db.supportsCTE, listReq)
		if err != nil {
			return -1, err
		}

		if len(resp.Entries) == 0 {
			return val, nil
		}

		if req.BySelectors != nil {
			switch req.BySelectors.Match {
			case datastore.Exact, datastore.Subset:
				resp.Entries = filterEntriesBySelectorSet(resp.Entries, req.BySelectors.Selectors)
			default:
			}
		}

		val += int32(len(resp.Entries))

		listReq.Pagination = resp.Pagination
	}
}

type idFilterNode struct {
	idColumn string

	// mutually exclusive with children
	// supports multiline query
	query []string

	// mutually exclusive with query
	children []idFilterNode
	union    bool
	name     string

	fixed bool
}

func (n idFilterNode) Render(builder *strings.Builder, dbType string, indentation int, eol bool) {
	n.render(builder, dbType, 0, indentation, true, eol)
}

func (n idFilterNode) render(builder *strings.Builder, dbType string, sibling int, indentation int, bol, eol bool) {
	if len(n.query) > 0 {
		if bol {
			indent(builder, indentation)
		}
		for idx, str := range n.query {
			if idx > 0 {
				indent(builder, indentation)
			}
			builder.WriteString(str)
			if idx+1 < len(n.query) {
				builder.WriteString("\n")
			}
		}
		if eol {
			builder.WriteString("\n")
		}
		return
	}

	if !n.fixed && len(n.children) == 1 {
		n.children[0].render(builder, dbType, sibling, indentation, bol, eol)
		return
	}

	if bol {
		indent(builder, indentation)
	}
	needsName := true
	switch {
	case n.union:
		builder.WriteString("SELECT e_id FROM (\n")
		for i, child := range n.children {
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("UNION\n")
			}
			child.render(builder, dbType, i, indentation+1, true, true)
		}
	case !isMySQLDbType(dbType):
		builder.WriteString("SELECT e_id FROM (\n")
		for i, child := range n.children {
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("INTERSECT\n")
			}
			child.render(builder, dbType, i, indentation+1, true, true)
		}
	default:
		needsName = false
		builder.WriteString("SELECT DISTINCT e_id FROM (\n")
		for i, child := range n.children {
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("INNER JOIN\n")
			}
			indent(builder, indentation+1)
			builder.WriteString("(")

			child.render(builder, dbType, i, indentation+1, false, false)
			builder.WriteString(") c_")
			builder.WriteString(strconv.Itoa(i))
			builder.WriteString("\n")
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("USING(e_id)\n")
			}
		}
	}
	indent(builder, indentation)
	builder.WriteString(")")
	if n.name != "" {
		builder.WriteString(" ")
		builder.WriteString(n.name)
	} else if needsName {
		builder.WriteString(" s_")
		builder.WriteString(strconv.Itoa(sibling))
	}
	if eol {
		builder.WriteString("\n")
	}
}

func indent(builder *strings.Builder, indentation int) {
	switch indentation {
	case 0:
	case 1:
		builder.WriteString("\t")
	case 2:
		builder.WriteString("\t\t")
	case 3:
		builder.WriteString("\t\t\t")
	case 4:
		builder.WriteString("\t\t\t\t")
	case 5:
		builder.WriteString("\t\t\t\t\t")
	default:
		for i := 0; i < indentation; i++ {
			builder.WriteString("\t")
		}
	}
}

func appendListRegistrationEntriesFilterQuery(filterExp string, builder *strings.Builder, dbType string, req *datastore.ListRegistrationEntriesRequest) (bool, []any, error) {
	var args []any

	root := idFilterNode{idColumn: "id"}

	if req.ByParentID != "" || req.BySpiffeID != "" {
		subquery := new(strings.Builder)
		subquery.WriteString("SELECT id AS e_id FROM registered_entries WHERE ")
		if req.ByParentID != "" {
			subquery.WriteString("parent_id = ?")
			args = append(args, req.ByParentID)
		}
		if req.BySpiffeID != "" {
			if req.ByParentID != "" {
				subquery.WriteString(" AND ")
			}
			subquery.WriteString("spiffe_id = ?")
			args = append(args, req.BySpiffeID)
		}
		root.children = append(root.children, idFilterNode{
			idColumn: "id",
			query:    []string{subquery.String()},
		})
	}

	if req.ByHint != "" {
		root.children = append(root.children, idFilterNode{
			idColumn: "id",
			query:    []string{"SELECT id AS e_id FROM registered_entries WHERE hint = ?"},
		})
		args = append(args, req.ByHint)
	}

	if req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
		switch req.BySelectors.Match {
		case datastore.Subset, datastore.MatchAny:
			// subset needs a union, so we need to group them and add the group
			// as a child to the root.
			if len(req.BySelectors.Selectors) < 2 {
				root.children = append(root.children, idFilterNode{
					idColumn: "registered_entry_id",
					query:    []string{"SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?"},
				})
			} else {
				group := idFilterNode{
					idColumn: "e_id",
					union:    true,
				}
				for range req.BySelectors.Selectors {
					group.children = append(group.children, idFilterNode{
						idColumn: "registered_entry_id",
						query:    []string{"SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?"},
					})
				}
				root.children = append(root.children, group)
			}
		case datastore.Exact, datastore.Superset:
			// exact match does use an intersection, so we can just add these
			// directly to the root idFilterNode, since it is already an intersection
			for range req.BySelectors.Selectors {
				root.children = append(root.children, idFilterNode{
					idColumn: "registered_entry_id",
					query:    []string{"SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?"},
				})
			}
		default:
			return false, nil, errs.New("unhandled selectors match behavior %q", req.BySelectors.Match)
		}
		for _, selector := range req.BySelectors.Selectors {
			args = append(args, selector.Type, selector.Value)
		}
	}

	if req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) > 0 {
		// Take the trust domains from the request without duplicates
		tdSet := make(map[string]struct{})
		for _, td := range req.ByFederatesWith.TrustDomains {
			tdSet[td] = struct{}{}
		}
		trustDomains := make([]string, 0, len(tdSet))
		for td := range tdSet {
			trustDomains = append(trustDomains, td)
		}

		// Exact/subset federates-with matching requires filtering out all registration
		// entries whose federated trust domains are not fully represented in the request
		filterNode := idFilterNode{
			idColumn: "E.id",
		}
		filterNode.query = append(filterNode.query, "SELECT E.id AS e_id")
		filterNode.query = append(filterNode.query, "FROM registered_entries E")
		filterNode.query = append(filterNode.query, "INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id")
		filterNode.query = append(filterNode.query, "INNER JOIN bundles B ON B.id = FE.bundle_id")
		filterNode.query = append(filterNode.query, "GROUP BY E.id")
		filterNode.query = append(filterNode.query, "HAVING")

		sliceArg := buildSliceArg(len(trustDomains))
		addIsSubset := func() {
			filterNode.query = append(filterNode.query, "\tCOUNT(CASE WHEN B.trust_domain NOT IN "+sliceArg+" THEN B.trust_domain ELSE NULL END) = 0 AND")
			for _, td := range trustDomains {
				args = append(args, td)
			}
		}

		switch req.ByFederatesWith.Match {
		case datastore.Subset:
			// Subset federates-with matching requires filtering out all registration
			// entries that don't federate with even one trust domain in the request
			addIsSubset()
			filterNode.query = append(filterNode.query, "\tCOUNT(CASE WHEN B.trust_domain IN "+sliceArg+" THEN B.trust_domain ELSE NULL END) > 0")
			for _, td := range trustDomains {
				args = append(args, td)
			}
		case datastore.Exact:
			// Exact federates-with matching requires filtering out all registration
			// entries that don't federate with all the trust domains in the request
			addIsSubset()
			filterNode.query = append(filterNode.query, "\tCOUNT(DISTINCT CASE WHEN B.trust_domain IN "+sliceArg+" THEN B.trust_domain ELSE NULL END) = ?")
			for _, td := range trustDomains {
				args = append(args, td)
			}
			args = append(args, len(trustDomains))
		case datastore.MatchAny:
			// MatchAny federates-with matching requires filtering out all registration
			// entries that has at least one trust domain in the request
			filterNode.query = append(filterNode.query, "\tCOUNT(CASE WHEN B.trust_domain IN "+sliceArg+" THEN B.trust_domain ELSE NULL END) > 0")
			for _, td := range trustDomains {
				args = append(args, td)
			}
		case datastore.Superset:
			// SuperSet federates-with matching requires filtering out all registration
			// entries has all trustdomains
			filterNode.query = append(filterNode.query, "\tCOUNT(DISTINCT CASE WHEN B.trust_domain IN "+sliceArg+" THEN B.trust_domain ELSE NULL END) = ?")
			for _, td := range trustDomains {
				args = append(args, td)
			}
			args = append(args, len(trustDomains))

		default:
			return false, nil, errs.New("unhandled federates with match behavior %q", req.ByFederatesWith.Match)
		}
		root.children = append(root.children, filterNode)
	}

	filtered := false
	filter := func() {
		if !filtered {
			builder.WriteString(filterExp)
		}
		filtered = true
	}

	indentation := 1
	if req.Pagination != nil && isMySQLDbType(dbType) {
		filter()
		builder.WriteString("\tSELECT e_id FROM (\n")
		indentation = 2
	}

	if len(root.children) > 0 {
		filter()
		root.Render(builder, dbType, indentation, req.Pagination == nil)
	}

	if req.Pagination != nil {
		filter()
		var idColumn string
		switch len(root.children) {
		case 0:
			idColumn = "id"
			indent(builder, indentation)
			builder.WriteString("SELECT id AS e_id FROM registered_entries")
		case 1:
			idColumn = root.children[0].idColumn
		default:
			idColumn = "e_id"
		}

		if len(req.Pagination.Token) > 0 {
			token, err := strconv.ParseUint(req.Pagination.Token, 10, 32)
			if err != nil {
				return false, nil, status.Errorf(codes.InvalidArgument, "could not parse token '%v'", req.Pagination.Token)
			}
			if len(root.children) == 1 && len(root.children[0].children) == 0 {
				builder.WriteString(" AND ")
			} else {
				builder.WriteString(" WHERE ")
			}
			builder.WriteString(idColumn)
			builder.WriteString(" > ?")
			args = append(args, token)
		}
		builder.WriteString(" ORDER BY ")
		builder.WriteString(idColumn)
		builder.WriteString(" ASC LIMIT ")
		builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))
		builder.WriteString("\n")

		if isMySQLDbType(dbType) {
			builder.WriteString("\t) workaround_for_mysql_subquery_limit\n")
		}
	}

	return filtered, args, nil
}

func buildSliceArg(length int) string {
	strBuilder := new(strings.Builder)
	strBuilder.WriteString("(?")
	for i := 1; i < length; i++ {
		strBuilder.WriteString(", ?")
	}
	strBuilder.WriteString(")")
	return strBuilder.String()
}

type nodeRow struct {
	EId             uint64
	SpiffeID        string
	DataType        sql.NullString
	SerialNumber    sql.NullString
	ExpiresAt       sql.NullTime
	NewSerialNumber sql.NullString
	NewExpiresAt    sql.NullTime
	CanReattest     sql.NullBool
	SelectorType    sql.NullString
	SelectorValue   sql.NullString
}

func scanNodeRow(rs *sql.Rows, r *nodeRow) error {
	return sqlError.Wrap(rs.Scan(
		&r.EId,
		&r.SpiffeID,
		&r.DataType,
		&r.SerialNumber,
		&r.ExpiresAt,
		&r.NewSerialNumber,
		&r.NewExpiresAt,
		&r.CanReattest,
		&r.SelectorType,
		&r.SelectorValue,
	))
}

func fillNodeFromRow(node *common.AttestedNode, r *nodeRow) error {
	if r.SpiffeID != "" {
		node.SpiffeId = r.SpiffeID
	}

	if r.DataType.Valid {
		node.AttestationDataType = r.DataType.String
	}

	if r.SerialNumber.Valid {
		node.CertSerialNumber = r.SerialNumber.String
	}

	if r.ExpiresAt.Valid {
		node.CertNotAfter = r.ExpiresAt.Time.Unix()
	}

	if r.NewExpiresAt.Valid {
		node.NewCertNotAfter = r.NewExpiresAt.Time.Unix()
	}

	if r.NewSerialNumber.Valid {
		node.NewCertSerialNumber = r.NewSerialNumber.String
	}

	if r.SelectorType.Valid {
		if !r.SelectorValue.Valid {
			return sqlError.New("expected non-nil selector.value value for attested node %s", node.SpiffeId)
		}
		node.Selectors = append(node.Selectors, &common.Selector{
			Type:  r.SelectorType.String,
			Value: r.SelectorValue.String,
		})
	}

	if r.CanReattest.Valid {
		node.CanReattest = r.CanReattest.Bool
	}

	return nil
}

type nodeSelectorRow struct {
	SpiffeID sql.NullString
	Type     sql.NullString
	Value    sql.NullString
}

func scanNodeSelectorRow(rs *sql.Rows, r *nodeSelectorRow) error {
	return sqlError.Wrap(rs.Scan(
		&r.SpiffeID,
		&r.Type,
		&r.Value,
	))
}

func fillNodeSelectorFromRow(nodeSelector *common.Selector, r *nodeSelectorRow) {
	if r.Type.Valid {
		nodeSelector.Type = r.Type.String
	}

	if r.Value.Valid {
		nodeSelector.Value = r.Value.String
	}
}

type entryRow struct {
	EId            uint64
	EntryID        sql.NullString
	SpiffeID       sql.NullString
	ParentID       sql.NullString
	RegTTL         sql.NullInt64
	Admin          sql.NullBool
	Downstream     sql.NullBool
	Expiry         sql.NullInt64
	SelectorID     sql.NullInt64
	SelectorType   sql.NullString
	SelectorValue  sql.NullString
	StoreSvid      sql.NullBool
	Hint           sql.NullString
	CreatedAt      sql.NullTime
	TrustDomain    sql.NullString
	DNSNameID      sql.NullInt64
	DNSName        sql.NullString
	RevisionNumber sql.NullInt64
	RegJwtSvidTTL  sql.NullInt64
}

func scanEntryRow(rs *sql.Rows, r *entryRow) error {
	return sqlError.Wrap(rs.Scan(
		&r.EId,
		&r.EntryID,
		&r.SpiffeID,
		&r.ParentID,
		&r.RegTTL,
		&r.Admin,
		&r.Downstream,
		&r.Expiry,
		&r.StoreSvid,
		&r.Hint,
		&r.CreatedAt,
		&r.SelectorID,
		&r.SelectorType,
		&r.SelectorValue,
		&r.TrustDomain,
		&r.DNSNameID,
		&r.DNSName,
		&r.RevisionNumber,
		&r.RegJwtSvidTTL,
	))
}

func fillEntryFromRow(entry *common.RegistrationEntry, r *entryRow) error {
	if r.EntryID.Valid {
		entry.EntryId = r.EntryID.String
	}
	if r.SpiffeID.Valid {
		entry.SpiffeId = r.SpiffeID.String
	}
	if r.ParentID.Valid {
		entry.ParentId = r.ParentID.String
	}
	if r.Admin.Valid {
		entry.Admin = r.Admin.Bool
	}
	if r.Downstream.Valid {
		entry.Downstream = r.Downstream.Bool
	}
	if r.Expiry.Valid {
		entry.EntryExpiry = r.Expiry.Int64
	}
	if r.StoreSvid.Valid {
		entry.StoreSvid = r.StoreSvid.Bool
	}
	if r.RevisionNumber.Valid {
		entry.RevisionNumber = r.RevisionNumber.Int64
	}
	if r.SelectorType.Valid {
		if !r.SelectorValue.Valid {
			return sqlError.New("expected non-nil selector.value value for entry id %s", entry.EntryId)
		}
		entry.Selectors = append(entry.Selectors, &common.Selector{
			Type:  r.SelectorType.String,
			Value: r.SelectorValue.String,
		})
	}
	if r.DNSName.Valid {
		entry.DnsNames = append(entry.DnsNames, r.DNSName.String)
	}
	if r.TrustDomain.Valid {
		entry.FederatesWith = append(entry.FederatesWith, r.TrustDomain.String)
	}
	if r.RegTTL.Valid {
		entry.X509SvidTtl = int32(r.RegTTL.Int64)
	}
	if r.RegJwtSvidTTL.Valid {
		entry.JwtSvidTtl = int32(r.RegJwtSvidTTL.Int64)
	}
	if r.Hint.Valid {
		entry.Hint = r.Hint.String
	}
	if r.CreatedAt.Valid {
		entry.CreatedAt = roundedInSecondsUnix(r.CreatedAt.Time)
	}

	return nil
}

// applyPagination  add order limit and token to current query
func applyPagination(p *datastore.Pagination, entryTx *gorm.DB) (*gorm.DB, error) {
	if p.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	entryTx = entryTx.Order("id asc").Limit(p.PageSize)

	if len(p.Token) > 0 {
		id, err := strconv.ParseUint(p.Token, 10, 32)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "could not parse token '%v'", p.Token)
		}
		entryTx = entryTx.Where("id > ?", id)
	}
	return entryTx, nil
}

func updateRegistrationEntry(tx *gorm.DB, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if err := validateRegistrationEntryForUpdate(e, mask); err != nil {
		return nil, err
	}

	// Get the existing entry
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", e.EntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}
	if mask == nil || mask.StoreSvid {
		entry.StoreSvid = e.StoreSvid
	}
	if mask == nil || mask.Selectors {
		// Delete existing selectors - we will write new ones
		if err := tx.Exec("DELETE FROM selectors WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		selectors := []Selector{}
		for _, s := range e.Selectors {
			selector := Selector{
				Type:  s.Type,
				Value: s.Value,
			}

			selectors = append(selectors, selector)
		}
		entry.Selectors = selectors
	}

	// Verify that final selectors contains the same 'type' when entry is used for store SVIDs
	if entry.StoreSvid && !equalSelectorTypes(entry.Selectors) {
		return nil, validationError.New("invalid registration entry: selector types must be the same when store SVID is enabled")
	}

	if mask == nil || mask.DnsNames {
		// Delete existing DNSs - we will write new ones
		if err := tx.Exec("DELETE FROM dns_names WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		dnsList := []DNSName{}
		for _, d := range e.DnsNames {
			dns := DNSName{
				Value: d,
			}

			dnsList = append(dnsList, dns)
		}
		entry.DNSList = dnsList
	}

	if mask == nil || mask.SpiffeId {
		entry.SpiffeID = e.SpiffeId
	}
	if mask == nil || mask.ParentId {
		entry.ParentID = e.ParentId
	}
	if mask == nil || mask.X509SvidTtl {
		entry.TTL = e.X509SvidTtl
	}
	if mask == nil || mask.Admin {
		entry.Admin = e.Admin
	}
	if mask == nil || mask.Downstream {
		entry.Downstream = e.Downstream
	}
	if mask == nil || mask.EntryExpiry {
		entry.Expiry = e.EntryExpiry
	}
	if mask == nil || mask.JwtSvidTtl {
		entry.JWTSvidTTL = e.JwtSvidTtl
	}
	if mask == nil || mask.Hint {
		entry.Hint = e.Hint
	}

	// Revision number is increased by 1 on every update call
	entry.RevisionNumber++

	if err := tx.Save(&entry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if mask == nil || mask.FederatesWith {
		federatesWith, err := makeFederatesWith(tx, e.FederatesWith)
		if err != nil {
			return nil, err
		}

		if err := tx.Model(&entry).Association("FederatesWith").Replace(federatesWith).Error; err != nil {
			return nil, err
		}
		// The FederatesWith field in entry is filled in by the call to modelToEntry below
	}

	returnEntry, err := modelToEntry(tx, entry)
	if err != nil {
		return nil, err
	}

	return returnEntry, nil
}

func deleteRegistrationEntry(tx *gorm.DB, entryID string) (*common.RegistrationEntry, error) {
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", entryID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	registrationEntry, err := modelToEntry(tx, entry)
	if err != nil {
		return nil, err
	}

	err = deleteRegistrationEntrySupport(tx, entry)
	if err != nil {
		return nil, err
	}

	return registrationEntry, nil
}

func deleteRegistrationEntrySupport(tx *gorm.DB, entry RegisteredEntry) error {
	if err := tx.Model(&entry).Association("FederatesWith").Clear().Error; err != nil {
		return err
	}

	if err := tx.Delete(&entry).Error; err != nil {
		return sqlError.Wrap(err)
	}

	// Delete existing selectors
	if err := tx.Exec("DELETE FROM selectors WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
		return sqlError.Wrap(err)
	}

	// Delete existing dns_names
	if err := tx.Exec("DELETE FROM dns_names WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func pruneRegistrationEntries(tx *gorm.DB, expiresBefore time.Time, logger logrus.FieldLogger) error {
	var registrationEntries []RegisteredEntry
	if err := tx.Where("expiry != 0").Where("expiry < ?", expiresBefore.Unix()).Find(&registrationEntries).Error; err != nil {
		return err
	}

	for _, entry := range registrationEntries {
		if err := deleteRegistrationEntrySupport(tx, entry); err != nil {
			return err
		}
		if err := createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{
			EntryID: entry.EntryID,
		}); err != nil {
			return err
		}
		logger.WithFields(logrus.Fields{
			telemetry.SPIFFEID:       entry.SpiffeID,
			telemetry.ParentID:       entry.ParentID,
			telemetry.RegistrationID: entry.EntryID,
		}).Info("Pruned an expired registration")
	}

	return nil
}

func createRegistrationEntryEvent(tx *gorm.DB, event *datastore.RegistrationEntryEvent) error {
	if err := tx.Create(&RegisteredEntryEvent{
		Model: Model{
			ID: event.EventID,
		},
		EntryID: event.EntryID,
	}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func fetchRegistrationEntryEvent(db *sqlDB, eventID uint) (*datastore.RegistrationEntryEvent, error) {
	event := RegisteredEntryEvent{}
	if err := db.Find(&event, "id = ?", eventID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.RegistrationEntryEvent{
		EventID: event.ID,
		EntryID: event.EntryID,
	}, nil
}

func deleteRegistrationEntryEvent(tx *gorm.DB, eventID uint) error {
	if err := tx.Delete(&RegisteredEntryEvent{
		Model: Model{
			ID: eventID,
		},
	}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func listRegistrationEntryEvents(tx *gorm.DB, req *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	var events []RegisteredEntryEvent

	if req.GreaterThanEventID != 0 || req.LessThanEventID != 0 {
		query, id, err := buildListEventsQueryString(req.GreaterThanEventID, req.LessThanEventID)
		if err != nil {
			return nil, sqlError.Wrap(err)
		}

		if err := tx.Find(&events, query.String(), id).Order("id asc").Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	} else {
		if err := tx.Find(&events).Order("id asc").Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	resp := &datastore.ListRegistrationEntryEventsResponse{
		Events: make([]datastore.RegistrationEntryEvent, len(events)),
	}
	for i, event := range events {
		resp.Events[i].EventID = event.ID
		resp.Events[i].EntryID = event.EntryID
	}

	return resp, nil
}

func pruneRegistrationEntryEvents(tx *gorm.DB, olderThan time.Duration) error {
	if err := tx.Where("created_at < ?", time.Now().Add(-olderThan)).Delete(&RegisteredEntryEvent{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func buildListEventsQueryString(greaterThanEventID, lessThanEventID uint) (*strings.Builder, uint, error) {
	if greaterThanEventID != 0 && lessThanEventID != 0 {
		return nil, 0, errors.New("can't set both greater and less than event id")
	}

	var id uint
	query := new(strings.Builder)
	query.WriteString("id ")
	if greaterThanEventID != 0 {
		query.WriteString("> ?")
		id = greaterThanEventID
	}
	if lessThanEventID != 0 {
		query.WriteString("< ?")
		id = lessThanEventID
	}

	return query, id, nil
}

func createJoinToken(tx *gorm.DB, token *datastore.JoinToken) error {
	t := JoinToken{
		Token:  token.Token,
		Expiry: token.Expiry.Unix(),
	}

	if err := tx.Create(&t).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func fetchJoinToken(tx *gorm.DB, token string) (*datastore.JoinToken, error) {
	var model JoinToken
	err := tx.Find(&model, "token = ?", token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToJoinToken(model), nil
}

func deleteJoinToken(tx *gorm.DB, token string) error {
	var model JoinToken
	if err := tx.Find(&model, "token = ?", token).Error; err != nil {
		return sqlError.Wrap(err)
	}

	if err := tx.Delete(&model).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func pruneJoinTokens(tx *gorm.DB, expiresBefore time.Time) error {
	if err := tx.Where("expiry < ?", expiresBefore.Unix()).Delete(&JoinToken{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func createFederationRelationship(tx *gorm.DB, fr *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	model := FederatedTrustDomain{
		TrustDomain:           fr.TrustDomain.Name(),
		BundleEndpointURL:     fr.BundleEndpointURL.String(),
		BundleEndpointProfile: string(fr.BundleEndpointProfile),
	}

	if fr.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
		model.EndpointSPIFFEID = fr.EndpointSPIFFEID.String()
	}

	if fr.TrustDomainBundle != nil {
		// overwrite current bundle
		_, err := setBundle(tx, fr.TrustDomainBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return fr, nil
}

func deleteFederationRelationship(tx *gorm.DB, trustDomain spiffeid.TrustDomain) error {
	model := new(FederatedTrustDomain)
	if err := tx.Find(model, "trust_domain = ?", trustDomain.Name()).Error; err != nil {
		return sqlError.Wrap(err)
	}
	if err := tx.Delete(model).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func fetchFederationRelationship(tx *gorm.DB, trustDomain spiffeid.TrustDomain) (*datastore.FederationRelationship, error) {
	var model FederatedTrustDomain
	err := tx.Find(&model, "trust_domain = ?", trustDomain.Name()).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	return modelToFederationRelationship(tx, &model)
}

// listFederationRelationships can be used to fetch all existing federation relationships.
func listFederationRelationships(tx *gorm.DB, req *datastore.ListFederationRelationshipsRequest) (*datastore.ListFederationRelationshipsResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	p := req.Pagination
	var err error
	if p != nil {
		tx, err = applyPagination(p, tx)
		if err != nil {
			return nil, err
		}
	}

	var federationRelationships []FederatedTrustDomain
	if err := tx.Find(&federationRelationships).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if p != nil {
		p.Token = ""
		// Set token only if page size is the same as federationRelationships len
		if len(federationRelationships) > 0 {
			lastEntry := federationRelationships[len(federationRelationships)-1]
			p.Token = fmt.Sprint(lastEntry.ID)
		}
	}

	resp := &datastore.ListFederationRelationshipsResponse{
		Pagination:              p,
		FederationRelationships: []*datastore.FederationRelationship{},
	}
	for _, model := range federationRelationships {
		model := model // alias the loop variable since we pass it by reference below
		federationRelationship, err := modelToFederationRelationship(tx, &model)
		if err != nil {
			return nil, err
		}

		resp.FederationRelationships = append(resp.FederationRelationships, federationRelationship)
	}

	return resp, nil
}

func updateFederationRelationship(tx *gorm.DB, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	var model FederatedTrustDomain
	err := tx.Find(&model, "trust_domain = ?", fr.TrustDomain.Name()).Error
	if err != nil {
		return nil, fmt.Errorf("unable to fetch federation relationship: %w", err)
	}

	if mask.BundleEndpointUrl {
		model.BundleEndpointURL = fr.BundleEndpointURL.String()
	}

	if mask.BundleEndpointProfile {
		model.BundleEndpointProfile = string(fr.BundleEndpointProfile)

		if fr.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
			model.EndpointSPIFFEID = fr.EndpointSPIFFEID.String()
		}
	}

	if mask.TrustDomainBundle && fr.TrustDomainBundle != nil {
		// overwrite current bundle
		_, err := setBundle(tx, fr.TrustDomainBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	if err := tx.Save(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToFederationRelationship(tx, &model)
}

func validateFederationRelationship(fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) error {
	if fr == nil {
		return status.Error(codes.InvalidArgument, "federation relationship is nil")
	}

	if fr.TrustDomain.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if mask.BundleEndpointUrl && fr.BundleEndpointURL == nil {
		return status.Error(codes.InvalidArgument, "bundle endpoint URL is required")
	}

	if mask.BundleEndpointProfile {
		switch fr.BundleEndpointProfile {
		case datastore.BundleEndpointWeb:
		case datastore.BundleEndpointSPIFFE:
			if fr.EndpointSPIFFEID.IsZero() {
				return status.Error(codes.InvalidArgument, "bundle endpoint SPIFFE ID is required")
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unknown bundle endpoint profile type: %q", fr.BundleEndpointProfile)
		}
	}

	return nil
}

func modelToFederationRelationship(tx *gorm.DB, model *FederatedTrustDomain) (*datastore.FederationRelationship, error) {
	bundleEndpointURL, err := url.Parse(model.BundleEndpointURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URL: %w", err)
	}

	td, err := spiffeid.TrustDomainFromString(model.TrustDomain)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	fr := &datastore.FederationRelationship{
		TrustDomain:           td,
		BundleEndpointURL:     bundleEndpointURL,
		BundleEndpointProfile: datastore.BundleEndpointType(model.BundleEndpointProfile),
	}

	switch fr.BundleEndpointProfile {
	case datastore.BundleEndpointWeb:
	case datastore.BundleEndpointSPIFFE:
		endpointSPIFFEID, err := spiffeid.FromString(model.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse bundle endpoint SPIFFE ID: %w", err)
		}
		fr.EndpointSPIFFEID = endpointSPIFFEID
	default:
		return nil, fmt.Errorf("unknown bundle endpoint profile type: %q", model.BundleEndpointProfile)
	}

	trustDomainBundle, err := fetchBundle(tx, td.IDString())
	if err != nil {
		return nil, fmt.Errorf("unable to fetch bundle: %w", err)
	}
	fr.TrustDomainBundle = trustDomainBundle

	return fr, nil
}

// modelToBundle converts the given bundle model to a Protobuf bundle message. It will also
// include any embedded CACert models.
func modelToBundle(model *Bundle) (*common.Bundle, error) {
	bundle := new(common.Bundle)
	if err := proto.Unmarshal(model.Data, bundle); err != nil {
		return nil, sqlError.Wrap(err)
	}

	return bundle, nil
}

func validateRegistrationEntry(entry *common.RegistrationEntry) error {
	if entry == nil {
		return validationError.New("invalid request: missing registered entry")
	}

	if len(entry.Selectors) == 0 {
		return validationError.New("invalid registration entry: missing selector list")
	}

	// In case of StoreSvid is set, all entries 'must' be the same type,
	// it is done to avoid users to mix selectors from different platforms in
	// entries with storable SVIDs
	if entry.StoreSvid {
		// Selectors must never be empty
		tpe := entry.Selectors[0].Type
		for _, t := range entry.Selectors {
			if tpe != t.Type {
				return validationError.New("invalid registration entry: selector types must be the same when store SVID is enabled")
			}
		}
	}

	if len(entry.EntryId) > 255 {
		return validationError.New("invalid registration entry: entry ID too long")
	}

	for _, e := range entry.EntryId {
		if !unicode.In(e, validEntryIDChars) {
			return validationError.New("invalid registration entry: entry ID contains invalid characters")
		}
	}

	if len(entry.SpiffeId) == 0 {
		return validationError.New("invalid registration entry: missing SPIFFE ID")
	}

	if entry.X509SvidTtl < 0 {
		return validationError.New("invalid registration entry: X509SvidTtl is not set")
	}

	if entry.JwtSvidTtl < 0 {
		return validationError.New("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}

// equalSelectorTypes validates that all selectors has the same type,
func equalSelectorTypes(selectors []Selector) bool {
	typ := ""
	for _, t := range selectors {
		switch {
		case typ == "":
			typ = t.Type
		case typ != t.Type:
			return false
		}
	}
	return true
}

func validateRegistrationEntryForUpdate(entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) error {
	if entry == nil {
		return validationError.New("invalid request: missing registered entry")
	}

	if (mask == nil || mask.Selectors) && len(entry.Selectors) == 0 {
		return validationError.New("invalid registration entry: missing selector list")
	}

	if (mask == nil || mask.SpiffeId) &&
		entry.SpiffeId == "" {
		return validationError.New("invalid registration entry: missing SPIFFE ID")
	}

	if (mask == nil || mask.X509SvidTtl) &&
		(entry.X509SvidTtl < 0) {
		return validationError.New("invalid registration entry: X509SvidTtl is not set")
	}

	if (mask == nil || mask.JwtSvidTtl) &&
		(entry.JwtSvidTtl < 0) {
		return validationError.New("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}

// bundleToModel converts the given Protobuf bundle message to a database model. It
// performs validation, and fully parses certificates to form CACert embedded models.
func bundleToModel(pb *common.Bundle) (*Bundle, error) {
	if pb == nil {
		return nil, sqlError.New("missing bundle in request")
	}
	data, err := proto.Marshal(pb)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &Bundle{
		TrustDomain: pb.TrustDomainId,
		Data:        data,
	}, nil
}

func modelToEntry(tx *gorm.DB, model RegisteredEntry) (*common.RegistrationEntry, error) {
	var fetchedSelectors []*Selector
	if err := tx.Model(&model).Related(&fetchedSelectors).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	selectors := make([]*common.Selector, 0, len(fetchedSelectors))
	for _, selector := range fetchedSelectors {
		selectors = append(selectors, &common.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		})
	}

	var fetchedDNSs []*DNSName
	if err := tx.Model(&model).Related(&fetchedDNSs).Order("registered_entry_id ASC").Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	var dnsList []string
	if len(fetchedDNSs) > 0 {
		dnsList = make([]string, 0, len(fetchedDNSs))
		for _, fetchedDNS := range fetchedDNSs {
			dnsList = append(dnsList, fetchedDNS.Value)
		}
	}

	var fetchedBundles []*Bundle
	if err := tx.Model(&model).Association("FederatesWith").Find(&fetchedBundles).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	var federatesWith []string
	for _, bundle := range fetchedBundles {
		federatesWith = append(federatesWith, bundle.TrustDomain)
	}

	return &common.RegistrationEntry{
		EntryId:        model.EntryID,
		Selectors:      selectors,
		SpiffeId:       model.SpiffeID,
		ParentId:       model.ParentID,
		X509SvidTtl:    model.TTL,
		FederatesWith:  federatesWith,
		Admin:          model.Admin,
		Downstream:     model.Downstream,
		EntryExpiry:    model.Expiry,
		DnsNames:       dnsList,
		RevisionNumber: model.RevisionNumber,
		StoreSvid:      model.StoreSvid,
		JwtSvidTtl:     model.JWTSvidTTL,
		Hint:           model.Hint,
		CreatedAt:      roundedInSecondsUnix(model.CreatedAt),
	}, nil
}

func createOrReturnEntryID(entry *common.RegistrationEntry) (string, error) {
	if entry.EntryId != "" {
		return entry.EntryId, nil
	}

	return newRegistrationEntryID()
}

func newRegistrationEntryID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func modelToAttestedNode(model AttestedNode) *common.AttestedNode {
	return &common.AttestedNode{
		SpiffeId:            model.SpiffeID,
		AttestationDataType: model.DataType,
		CertSerialNumber:    model.SerialNumber,
		CertNotAfter:        model.ExpiresAt.Unix(),
		NewCertSerialNumber: model.NewSerialNumber,
		NewCertNotAfter:     nullableDBTimeToUnixTime(model.NewExpiresAt),
		CanReattest:         model.CanReattest,
	}
}

func modelToJoinToken(model JoinToken) *datastore.JoinToken {
	return &datastore.JoinToken{
		Token:  model.Token,
		Expiry: time.Unix(model.Expiry, 0),
	}
}

func modelToCAJournal(model CAJournal) *datastore.CAJournal {
	return &datastore.CAJournal{
		ID:                    model.ID,
		Data:                  model.Data,
		ActiveX509AuthorityID: model.ActiveX509AuthorityID,
	}
}

func makeFederatesWith(tx *gorm.DB, ids []string) ([]*Bundle, error) {
	var bundles []*Bundle
	if err := tx.Where("trust_domain in (?)", ids).Find(&bundles).Error; err != nil {
		return nil, err
	}

	// make sure all of the ids were found
	idset := make(map[string]bool)
	for _, bundle := range bundles {
		idset[bundle.TrustDomain] = true
	}

	for _, id := range ids {
		if !idset[id] {
			return nil, fmt.Errorf("unable to find federated bundle %q", id)
		}
	}

	return bundles, nil
}

func bindVars(db *gorm.DB, query string) string {
	dialect := db.Dialect()
	if dialect.BindVar(1) == "?" {
		return query
	}

	return bindVarsFn(dialect.BindVar, query)
}

func bindVarsFn(fn func(int) string, query string) string {
	var buf bytes.Buffer
	var n int
	for i := strings.Index(query, "?"); i != -1; i = strings.Index(query, "?") {
		n++
		buf.WriteString(query[:i])
		buf.WriteString(fn(n))
		query = query[i+1:]
	}
	buf.WriteString(query)
	return buf.String()
}

func (cfg *configuration) Validate() error {
	if cfg.databaseTypeConfig.databaseType == "" {
		return sqlError.New("database_type must be set")
	}

	if cfg.ConnectionString == "" {
		return sqlError.New("connection_string must be set")
	}

	if isMySQLDbType(cfg.databaseTypeConfig.databaseType) {
		if err := validateMySQLConfig(cfg, false); err != nil {
			return err
		}

		if cfg.RoConnectionString != "" {
			if err := validateMySQLConfig(cfg, true); err != nil {
				return err
			}
		}
	}

	if cfg.databaseTypeConfig.AWSMySQL != nil {
		if err := cfg.databaseTypeConfig.AWSMySQL.validate(); err != nil {
			return err
		}
	}

	if cfg.databaseTypeConfig.AWSPostgres != nil {
		if err := cfg.databaseTypeConfig.AWSPostgres.validate(); err != nil {
			return err
		}
	}

	return nil
}

// getConnectionString returns the connection string corresponding to the database connection.
func getConnectionString(cfg *configuration, isReadOnly bool) string {
	connectionString := cfg.ConnectionString
	if isReadOnly {
		connectionString = cfg.RoConnectionString
	}
	return connectionString
}

func queryVersion(gormDB *gorm.DB, query string) (string, error) {
	db := gormDB.DB()
	if db == nil {
		return "", sqlError.New("unable to get raw database object")
	}

	var version string
	if err := db.QueryRow(query).Scan(&version); err != nil {
		return "", sqlError.Wrap(err)
	}
	return version, nil
}

func nullableDBTimeToUnixTime(dbTime *time.Time) int64 {
	if dbTime == nil {
		return 0
	}
	return dbTime.Unix()
}

func nullableUnixTimeToDBTime(unixTime int64) *time.Time {
	if unixTime == 0 {
		return nil
	}
	dbTime := time.Unix(unixTime, 0)
	return &dbTime
}

func lookupSimilarEntry(ctx context.Context, db *sqlDB, tx *gorm.DB, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	resp, err := listRegistrationEntriesOnce(ctx, tx.CommonDB().(queryContext), db.databaseType, db.supportsCTE, &datastore.ListRegistrationEntriesRequest{
		BySpiffeID: entry.SpiffeId,
		ByParentID: entry.ParentId,
		BySelectors: &datastore.BySelectors{
			Match:     datastore.Exact,
			Selectors: entry.Selectors,
		},
	})
	if err != nil {
		return nil, err
	}

	// listRegistrationEntriesOnce returns both exact and superset matches.
	// Filter out the superset matches to get an exact match
	entries := filterEntriesBySelectorSet(resp.Entries, entry.Selectors)
	if len(entries) > 0 {
		return entries[0], nil
	}

	return nil, nil
}

// roundedInSecondsUnix rounds the time to the nearest second, and return the time in seconds since the
// unix epoch. This function is used to avoid issues with databases versions that do not support sub-second precision.
func roundedInSecondsUnix(t time.Time) int64 {
	return t.Round(time.Second).Unix()
}

func createCAJournal(tx *gorm.DB, caJournal *datastore.CAJournal) (*datastore.CAJournal, error) {
	model := CAJournal{
		Data:                  caJournal.Data,
		ActiveX509AuthorityID: caJournal.ActiveX509AuthorityID,
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToCAJournal(model), nil
}

func fetchCAJournal(tx *gorm.DB, activeX509AuthorityID string) (*datastore.CAJournal, error) {
	var model CAJournal
	err := tx.Find(&model, "active_x509_authority_id = ?", activeX509AuthorityID).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	return modelToCAJournal(model), nil
}

func listCAJournalsForTesting(tx *gorm.DB) (caJournals []*datastore.CAJournal, err error) {
	var caJournalsModel []CAJournal
	if err := tx.Find(&caJournals).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	for _, model := range caJournalsModel {
		model := model // alias the loop variable since we pass it by reference below
		caJournals = append(caJournals, modelToCAJournal(model))
	}
	return caJournals, nil
}

func updateCAJournal(tx *gorm.DB, caJournal *datastore.CAJournal) (*datastore.CAJournal, error) {
	var model CAJournal
	if err := tx.Find(&model, "id = ?", caJournal.ID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	model.ActiveX509AuthorityID = caJournal.ActiveX509AuthorityID
	model.Data = caJournal.Data

	if err := tx.Save(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToCAJournal(model), nil
}

func validateCAJournal(caJournal *datastore.CAJournal) error {
	if caJournal == nil {
		return status.Error(codes.InvalidArgument, "ca journal is required")
	}

	return nil
}

func deleteCAJournal(tx *gorm.DB, caJournalID uint) error {
	model := new(CAJournal)
	if err := tx.Find(model, "id = ?", caJournalID).Error; err != nil {
		return sqlError.Wrap(err)
	}
	if err := tx.Delete(model).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func parseDatabaseTypeASTNode(node ast.Node) (*dbTypeConfig, error) {
	lt, ok := node.(*ast.LiteralType)
	if ok {
		return &dbTypeConfig{databaseType: strings.Trim(lt.Token.Text, "\"")}, nil
	}

	// We expect the node to be *ast.ObjectList.
	objectList, ok := node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("malformed database type configuration")
	}

	if len(objectList.Items) != 1 {
		return nil, errors.New("exactly one database type is expected")
	}

	if len(objectList.Items[0].Keys) != 1 {
		return nil, errors.New("exactly one key is expected")
	}

	var data bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&data, node); err != nil {
		return nil, err
	}

	dbTypeConfig := new(dbTypeConfig)
	if err := hcl.Decode(dbTypeConfig, data.String()); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	databaseType := strings.Trim(objectList.Items[0].Keys[0].Token.Text, "\"")
	switch databaseType {
	case AWSMySQL:
	case AWSPostgreSQL:
	default:
		return nil, fmt.Errorf("unknown database type: %s", databaseType)
	}

	dbTypeConfig.databaseType = databaseType
	return dbTypeConfig, nil
}

func isMySQLDbType(dbType string) bool {
	return dbType == MySQL || dbType == AWSMySQL
}

func isPostgresDbType(dbType string) bool {
	return dbType == PostgreSQL || dbType == AWSPostgreSQL
}

func isSQLiteDbType(dbType string) bool {
	return dbType == SQLite
}

func calculateResultPreallocation(pagination *datastore.Pagination) int32 {
	switch {
	case pagination == nil:
		return 64
	case pagination.PageSize < maxResultPreallocation:
		return pagination.PageSize
	default:
		return maxResultPreallocation
	}
}
