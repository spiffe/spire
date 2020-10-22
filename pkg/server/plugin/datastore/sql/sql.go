package sql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/jinzhu/gorm"

	_ "github.com/jinzhu/gorm/dialects/sqlite" // gorm sqlite dialect init registration
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	pluginInfo = spi.GetPluginInfoResponse{
		Description: "",
		DateCreated: "",
		Version:     "",
		Author:      "",
		Company:     "",
	}

	sqlError = errs.Class("datastore-sql")
)

const (
	// MySQL database type
	MySQL = "mysql"
	// PostgreSQL database type
	PostgreSQL = "postgres"
	// SQLite database type
	SQLite = "sqlite3"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin("sql",
		datastore.PluginServer(p),
	)
}

// Configuration for the datastore.
// Pointer values are used to distinguish between "unset" and "zero" values.
type configuration struct {
	DatabaseType       string  `hcl:"database_type" json:"database_type"`
	ConnectionString   string  `hcl:"connection_string" json:"connection_string"`
	RoConnectionString string  `hcl:"ro_connection_string" json:"ro_connection_string"`
	RootCAPath         string  `hcl:"root_ca_path" json:"root_ca_path"`
	ClientCertPath     string  `hcl:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath      string  `hcl:"client_key_path" json:"client_key_path"`
	ConnMaxLifetime    *string `hcl:"conn_max_lifetime" json:"conn_max_lifetime"`
	MaxOpenConns       *int    `hcl:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns       *int    `hcl:"max_idle_conns" json:"max_idle_conns"`
	DisableMigration   bool    `hcl:"disable_migration" json:"disable_migration"`

	// Undocumented flags
	LogSQL bool `hcl:"log_sql" json:"log_sql"`
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

func (db *sqlDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	stmt, err := db.stmtCache.get(ctx, query)
	if err != nil {
		return nil, err
	}
	return stmt.QueryContext(ctx, args...)
}

// Plugin is a DataStore plugin implemented via a SQL database
type Plugin struct {
	mu   sync.Mutex
	db   *sqlDB
	roDb *sqlDB
	log  hclog.Logger
}

// New creates a new sql plugin struct. Configure must be called
// in order to start the db.
func New() *Plugin {
	return &Plugin{}
}

func (ds *Plugin) SetLogger(logger hclog.Logger) {
	ds.log = logger
}

// CreateBundle stores the given bundle
func (ds *Plugin) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (resp *datastore.CreateBundleResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *Plugin) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (resp *datastore.UpdateBundleResponse, err error) {
	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *Plugin) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (resp *datastore.SetBundleResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = setBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *Plugin) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (resp *datastore.AppendBundleResponse, err error) {
	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = appendBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *Plugin) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (resp *datastore.DeleteBundleResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *Plugin) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (resp *datastore.FetchBundleResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CountBundles can be used to count all existing bundles.
func (ds *Plugin) CountBundles(ctx context.Context, req *datastore.CountBundlesRequest) (resp *datastore.CountBundlesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = countBundles(tx)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
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
func (ds *Plugin) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (resp *datastore.PruneBundleResponse, err error) {
	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneBundle(tx, req, ds.log)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// CreateAttestedNode stores the given attested node
func (ds *Plugin) CreateAttestedNode(ctx context.Context,
	req *datastore.CreateAttestedNodeRequest) (resp *datastore.CreateAttestedNodeResponse, err error) {
	if req.Node == nil {
		return nil, sqlError.New("invalid request: missing attested node")
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchAttestedNode fetches an existing attested node by SPIFFE ID
func (ds *Plugin) FetchAttestedNode(ctx context.Context,
	req *datastore.FetchAttestedNodeRequest) (resp *datastore.FetchAttestedNodeResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CountAttestedNodes counts all attested nodes
func (ds *Plugin) CountAttestedNodes(ctx context.Context,
	req *datastore.CountAttestedNodesRequest) (resp *datastore.CountAttestedNodesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = countAttestedNodes(tx)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// ListAttestedNodes lists all attested nodes (pagination available)
func (ds *Plugin) ListAttestedNodes(ctx context.Context,
	req *datastore.ListAttestedNodesRequest) (resp *datastore.ListAttestedNodesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodes(ctx, ds.db, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateAttestedNode updates the given node's cert serial and expiration.
func (ds *Plugin) UpdateAttestedNode(ctx context.Context,
	req *datastore.UpdateAttestedNodeRequest) (resp *datastore.UpdateAttestedNodeResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteAttestedNode deletes the given attested node
func (ds *Plugin) DeleteAttestedNode(ctx context.Context,
	req *datastore.DeleteAttestedNodeRequest) (resp *datastore.DeleteAttestedNodeResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// SetNodeSelectors sets node (agent) selectors by SPIFFE ID, deleting old selectors first
func (ds *Plugin) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (resp *datastore.SetNodeSelectorsResponse, err error) {
	if req.Selectors == nil {
		return nil, errors.New("invalid request: missing selectors")
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = setNodeSelectors(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// GetNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *Plugin) GetNodeSelectors(ctx context.Context,
	req *datastore.GetNodeSelectorsRequest) (resp *datastore.GetNodeSelectorsResponse, err error) {
	if req.TolerateStale && ds.roDb != nil {
		return getNodeSelectors(ctx, ds.roDb, req)
	}
	return getNodeSelectors(ctx, ds.db, req)
}

// ListNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *Plugin) ListNodeSelectors(ctx context.Context,
	req *datastore.ListNodeSelectorsRequest) (resp *datastore.ListNodeSelectorsResponse, err error) {
	if req.TolerateStale && ds.roDb != nil {
		return listNodeSelectors(ctx, ds.roDb, req)
	}
	return listNodeSelectors(ctx, ds.db, req)
}

// CreateRegistrationEntry stores the given registration entry
func (ds *Plugin) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (resp *datastore.CreateRegistrationEntryResponse, err error) {
	// TODO: Validations should be done in the ProtoBuf level [https://github.com/spiffe/spire/issues/44]
	if err = validateRegistrationEntry(req.Entry); err != nil {
		return nil, err
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
func (ds *Plugin) FetchRegistrationEntry(ctx context.Context,
	req *datastore.FetchRegistrationEntryRequest) (resp *datastore.FetchRegistrationEntryResponse, err error) {
	return fetchRegistrationEntry(ctx, ds.db, req)
}

// CounCountRegistrationEntries counts all registrations (pagination available)
func (ds *Plugin) CountRegistrationEntries(ctx context.Context,
	req *datastore.CountRegistrationEntriesRequest) (resp *datastore.CountRegistrationEntriesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = countRegistrationEntries(tx)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *Plugin) ListRegistrationEntries(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest) (resp *datastore.ListRegistrationEntriesResponse, err error) {
	if req.TolerateStale && ds.roDb != nil {
		return listRegistrationEntries(ctx, ds.roDb, req)
	}
	return listRegistrationEntries(ctx, ds.db, req)
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *Plugin) UpdateRegistrationEntry(ctx context.Context,
	req *datastore.UpdateRegistrationEntryRequest) (resp *datastore.UpdateRegistrationEntryResponse, err error) {
	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteRegistrationEntry deletes the given registration
func (ds *Plugin) DeleteRegistrationEntry(ctx context.Context,
	req *datastore.DeleteRegistrationEntryRequest) (resp *datastore.DeleteRegistrationEntryResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
// before the date in the message
func (ds *Plugin) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (resp *datastore.PruneRegistrationEntriesResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneRegistrationEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateJoinToken takes a Token message and stores it
func (ds *Plugin) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (resp *datastore.CreateJoinTokenResponse, err error) {
	if req.JoinToken == nil || req.JoinToken.Token == "" || req.JoinToken.Expiry == 0 {
		return nil, errors.New("token and expiry are required")
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchJoinToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (ds *Plugin) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (resp *datastore.FetchJoinTokenResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteJoinToken deletes the given join token
func (ds *Plugin) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (resp *datastore.DeleteJoinTokenResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneJoinTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *Plugin) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (resp *datastore.PruneJoinTokensResponse, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneJoinTokens(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// Configure parses HCL config payload into config struct, and opens new DB based on the result
func (ds *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &configuration{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if err := ds.openConnection(config, false); err != nil {
		return nil, err
	}

	if config.RoConnectionString == "" {
		return &spi.ConfigureResponse{}, nil
	}

	if err := ds.openConnection(config, true); err != nil {
		return nil, err
	}

	return &spi.ConfigureResponse{}, nil
}

func (ds *Plugin) openConnection(config *configuration, isReadOnly bool) error {
	connectionString := getConnectionString(config, isReadOnly)
	sqlDb := ds.db
	if isReadOnly {
		sqlDb = ds.roDb
	}

	if sqlDb == nil || connectionString != sqlDb.connectionString || config.DatabaseType != ds.db.databaseType {
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

		ds.log.Info("Connected to SQL database",
			"type", config.DatabaseType,
			"version", version,
			"read_only", isReadOnly,
		)

		sqlDb = &sqlDB{
			DB:               db,
			raw:              raw,
			databaseType:     config.DatabaseType,
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

func (ds *Plugin) closeDB() {
	if ds.db != nil {
		ds.db.Close()
	}

	if ds.roDb != nil {
		ds.roDb.Close()
	}
}

// GetPluginInfo returns the sql plugin
func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (ds *Plugin) withWriteRepeatableReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
}

func (ds *Plugin) withWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, nil)
}

func (ds *Plugin) withReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, true, nil)
}

func (ds *Plugin) withTx(ctx context.Context, op func(tx *gorm.DB) error, readOnly bool, opts *sql.TxOptions) error {
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

	tx := db.BeginTx(ctx, opts)
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

	ds.log.Info("Opening SQL database", telemetry.DatabaseType, cfg.DatabaseType)
	switch cfg.DatabaseType {
	case SQLite:
		dialect = sqliteDB{log: ds.log}
	case PostgreSQL:
		dialect = postgresDB{}
	case MySQL:
		dialect = mysqlDB{}
	default:
		return nil, "", false, nil, sqlError.New("unsupported database_type: %v", cfg.DatabaseType)
	}

	db, version, supportsCTE, err := dialect.connect(cfg, isReadOnly)
	if err != nil {
		return nil, "", false, nil, err
	}

	gormLogger := ds.log.Named("gorm")
	gormLogger.SetLevel(hclog.Debug)
	db.SetLogger(gormLogger.StandardLogger(&hclog.StandardLoggerOptions{
		InferLevels: true,
	}))
	if cfg.MaxOpenConns != nil {
		db.DB().SetMaxOpenConns(*cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != nil {
		db.DB().SetMaxIdleConns(*cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime != nil {
		connMaxLifetime, err := time.ParseDuration(*cfg.ConnMaxLifetime)
		if err != nil {
			return nil, "", false, nil, fmt.Errorf("failed to parse conn_max_lifetime %q: %v", *cfg.ConnMaxLifetime, err)
		}
		db.DB().SetConnMaxLifetime(connMaxLifetime)
	}

	if !isReadOnly {
		if err := migrateDB(db, cfg.DatabaseType, cfg.DisableMigration, ds.log); err != nil {
			db.Close()
			return nil, "", false, nil, err
		}
	}

	return db, version, supportsCTE, dialect, nil
}

func createBundle(tx *gorm.DB, req *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	model, err := bundleToModel(req.Bundle)
	if err != nil {
		return nil, err
	}

	if err := tx.Create(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.CreateBundleResponse{
		Bundle: req.Bundle,
	}, nil
}

func updateBundle(tx *gorm.DB, req *datastore.UpdateBundleRequest) (*datastore.UpdateBundleResponse, error) {
	newBundle := req.Bundle
	newModel, err := bundleToModel(newBundle)
	if err != nil {
		return nil, err
	}

	model := &Bundle{}
	if err := tx.Find(model, "trust_domain = ?", newModel.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	model.Data, newBundle, err = applyBundleMask(model, newBundle, req.InputMask)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Save(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.UpdateBundleResponse{
		Bundle: newBundle,
	}, nil
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

	newModel, err := bundleToModel(bundle)
	if err != nil {
		return nil, nil, err
	}

	return newModel.Data, bundle, nil
}

func setBundle(tx *gorm.DB, req *datastore.SetBundleRequest) (*datastore.SetBundleResponse, error) {
	newModel, err := bundleToModel(req.Bundle)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.RecordNotFound() {
		resp, err := createBundle(tx, &datastore.CreateBundleRequest{Bundle: req.Bundle})
		if err != nil {
			return nil, err
		}
		return &datastore.SetBundleResponse{
			Bundle: resp.Bundle,
		}, nil
	} else if result.Error != nil {
		return nil, sqlError.Wrap(result.Error)
	}

	resp, err := updateBundle(tx, &datastore.UpdateBundleRequest{Bundle: req.Bundle})
	if err != nil {
		return nil, err
	}
	return &datastore.SetBundleResponse{
		Bundle: resp.Bundle,
	}, nil
}

func appendBundle(tx *gorm.DB, req *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	newModel, err := bundleToModel(req.Bundle)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.RecordNotFound() {
		resp, err := createBundle(tx, &datastore.CreateBundleRequest{Bundle: req.Bundle})
		if err != nil {
			return nil, err
		}
		return &datastore.AppendBundleResponse{
			Bundle: resp.Bundle,
		}, nil
	} else if result.Error != nil {
		return nil, sqlError.Wrap(result.Error)
	}

	// parse the bundle data and add missing elements
	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	bundle, changed := bundleutil.MergeBundles(bundle, req.Bundle)
	if changed {
		newModel, err := bundleToModel(bundle)
		if err != nil {
			return nil, err
		}
		model.Data = newModel.Data
		if err := tx.Save(model).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	return &datastore.AppendBundleResponse{
		Bundle: bundle,
	}, nil
}

func deleteBundle(tx *gorm.DB, req *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	trustDomainID, err := idutil.NormalizeSpiffeID(req.TrustDomainId, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	model := new(Bundle)
	if err := tx.Find(model, "trust_domain = ?", trustDomainID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Get a count of associated registration entries
	entriesAssociation := tx.Model(model).Association("FederatedEntries")
	entriesCount := entriesAssociation.Count()
	if err := entriesAssociation.Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if entriesCount > 0 {
		switch req.Mode {
		case datastore.DeleteBundleRequest_DELETE:
			// TODO: figure out how to do this gracefully with GORM.
			if err := tx.Exec(bindVars(tx, `DELETE FROM registered_entries WHERE id in (
				SELECT
					registered_entry_id
				FROM
					federated_registration_entries
				WHERE
					bundle_id = ?)`), model.ID).Error; err != nil {
				return nil, sqlError.Wrap(err)
			}
		case datastore.DeleteBundleRequest_DISSOCIATE:
			if err := entriesAssociation.Clear().Error; err != nil {
				return nil, sqlError.Wrap(err)
			}
		default:
			return nil, status.Newf(codes.FailedPrecondition, "datastore-sql: cannot delete bundle; federated with %d registration entries", entriesCount).Err()
		}
	}

	if err := tx.Delete(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return &datastore.DeleteBundleResponse{
		Bundle: bundle,
	}, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func fetchBundle(tx *gorm.DB, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	trustDomainID, err := idutil.NormalizeSpiffeID(req.TrustDomainId, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	model := new(Bundle)
	err = tx.Find(model, "trust_domain = ?", trustDomainID).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchBundleResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return &datastore.FetchBundleResponse{
		Bundle: bundle,
	}, nil
}

// countBundles can be used to count existing bundles
func countBundles(tx *gorm.DB) (*datastore.CountBundlesResponse, error) {
	tx = tx.Model(&Bundle{})

	var count int
	if err := tx.Count(&count).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.CountBundlesResponse{
		Bundles: int32(count),
	}
	return resp, nil
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

func pruneBundle(tx *gorm.DB, req *datastore.PruneBundleRequest, log hclog.Logger) (*datastore.PruneBundleResponse, error) {
	// Get current bundle
	current, err := fetchBundle(tx, &datastore.FetchBundleRequest{TrustDomainId: req.TrustDomainId})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current bundle: %v", err)
	}

	if current.Bundle == nil {
		// No bundle to prune
		return &datastore.PruneBundleResponse{}, nil
	}

	// Prune
	newBundle, changed, err := bundleutil.PruneBundle(current.Bundle, time.Unix(req.ExpiresBefore, 0), log)
	if err != nil {
		return nil, fmt.Errorf("prune failed: %v", err)
	}

	// Update only if bundle was modified
	if changed {
		_, err := updateBundle(tx, &datastore.UpdateBundleRequest{
			Bundle: newBundle,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to write new bundle: %v", err)
		}
	}

	return &datastore.PruneBundleResponse{BundleChanged: changed}, nil
}

func createAttestedNode(tx *gorm.DB, req *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	model := AttestedNode{
		SpiffeID:        req.Node.SpiffeId,
		DataType:        req.Node.AttestationDataType,
		SerialNumber:    req.Node.CertSerialNumber,
		ExpiresAt:       time.Unix(req.Node.CertNotAfter, 0),
		NewSerialNumber: req.Node.NewCertSerialNumber,
		NewExpiresAt:    nullableUnixTimeToDBTime(req.Node.NewCertNotAfter),
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.CreateAttestedNodeResponse{
		Node: modelToAttestedNode(model),
	}, nil
}

func fetchAttestedNode(tx *gorm.DB, req *datastore.FetchAttestedNodeRequest) (*datastore.FetchAttestedNodeResponse, error) {
	var model AttestedNode
	err := tx.Find(&model, "spiffe_id = ?", req.SpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchAttestedNodeResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}
	return &datastore.FetchAttestedNodeResponse{
		Node: modelToAttestedNode(model),
	}, nil
}

func countAttestedNodes(tx *gorm.DB) (*datastore.CountAttestedNodesResponse, error) {
	var count int
	if err := tx.Model(&AttestedNode{}).Count(&count).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.CountAttestedNodesResponse{
		Nodes: int32(count),
	}
	return resp, nil
}

func listAttestedNodes(ctx context.Context, db *sqlDB, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
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

		resp.Nodes = filterNodesBySelectorSet(resp.Nodes, req.BySelectorMatch.Selectors)

		if len(resp.Nodes) > 0 || resp.Pagination == nil || len(resp.Pagination.Token) == 0 {
			return resp, nil
		}

		req.Pagination = resp.Pagination
	}
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

	var nodes []*common.AttestedNode
	if req.Pagination != nil {
		nodes = make([]*common.AttestedNode, 0, req.Pagination.PageSize)
	} else {
		nodes = make([]*common.AttestedNode, 0, 64)
	}

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

func buildListAttestedNodesQuery(dbType string, supportsCTE bool, req *datastore.ListAttestedNodesRequest) (string, []interface{}, error) {
	switch dbType {
	case SQLite:
		return buildListAttestedNodesQueryCTE(req, dbType)
	case PostgreSQL:
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		query, args, err := buildListAttestedNodesQueryCTE(req, dbType)
		if err != nil {
			return query, args, err
		}
		return postgreSQLRebind(query), args, nil
	case MySQL:
		if supportsCTE {
			return buildListAttestedNodesQueryCTE(req, dbType)
		}
		return buildListAttestedNodesQueryMySQL(req)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildListAttestedNodesQueryCTE(req *datastore.ListAttestedNodesRequest, dbType string) (string, []interface{}, error) {
	builder := new(strings.Builder)
	var args []interface{}

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
	if req.ByExpiresBefore != nil {
		builder.WriteString("\t\tAND expires_at < ?\n")
		args = append(args, time.Unix(req.ByExpiresBefore.Value, 0))
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
		if req.ByBanned.Value {
			builder.WriteString("\t\tAND serial_number = ''\n")
		} else {
			builder.WriteString("\t\tAND serial_number <> ''\n")
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
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,`)

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
	if req.Pagination != nil && dbType == MySQL {
		builder.WriteString("\tSELECT id FROM (\n")
	}

	// Add filter by selectors
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) > 0 {
		// Select IDs, that will be used to fetch "paged" entrieSelect IDs, that will be used to fetch "paged" entries
		builder.WriteString("\tSELECT DISTINCT id FROM (\n")

		query := "SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?"

		switch req.BySelectorMatch.Match {
		case datastore.BySelectors_MATCH_SUBSET:
			// Subset needs a union, so we need to group them and add the group
			// as a child to the root
			for i := range req.BySelectorMatch.Selectors {
				builder.WriteString("\t\t")
				builder.WriteString(query)
				if i < (len(req.BySelectorMatch.Selectors) - 1) {
					builder.WriteString("\n\t\tUNION\n")
				}
			}
		case datastore.BySelectors_MATCH_EXACT:
			for i := range req.BySelectorMatch.Selectors {
				switch dbType {
				// MySQL does not support INTERSECT, so use INNER JOIN instead
				case MySQL:
					builder.WriteString("\t\t(")
					builder.WriteString(query)
					builder.WriteString(fmt.Sprintf(") c_%d\n", i))
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

		builder.WriteString("\n\t) ")
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

	if dbType == PostgreSQL ||
		(req.BySelectorMatch != nil && req.BySelectorMatch.Match == datastore.BySelectors_MATCH_SUBSET) {
		builder.WriteString(" AS result_nodes")
	}
	if req.Pagination != nil {
		builder.WriteString(" ORDER BY id ASC LIMIT ")
		builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))

		// Add workaround for limit
		if dbType == MySQL {
			builder.WriteString("\n\t) workaround_for_mysql_subquery_limit")
		}
	}

	builder.WriteString("\n)\n")

	return builder.String(), args, nil
}

func buildListAttestedNodesQueryMySQL(req *datastore.ListAttestedNodesRequest) (string, []interface{}, error) {
	builder := new(strings.Builder)
	var args []interface{}

	// Selectors will be fetched only when `FetchSelectors` or `BySelectorMatch` are in request
	fetchSelectors := req.FetchSelectors || req.BySelectorMatch != nil

	// Add expected fields
	builder.WriteString(`
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,`)

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

		// Filter by paginatioin token
		if req.Pagination != nil && req.Pagination.Token != "" {
			token, err := strconv.ParseUint(req.Pagination.Token, 10, 32)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "could not parse token '%v'", req.Pagination.Token)
			}
			builder.WriteString(" AND N.id > ?")
			args = append(args, token)
		}

		// Filter by expiration
		if req.ByExpiresBefore != nil {
			builder.WriteString(" AND N.expires_at < ?")
			args = append(args, time.Unix(req.ByExpiresBefore.Value, 0))
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
			if req.ByBanned.Value {
				builder.WriteString(" AND N.serial_number = ''")
			} else {
				builder.WriteString(" AND N.serial_number <> ''")
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
			case datastore.BySelectors_MATCH_SUBSET:
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
			case datastore.BySelectors_MATCH_EXACT:
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
func updateAttestedNode(tx *gorm.DB, req *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	var model AttestedNode
	if err := tx.Find(&model, "spiffe_id = ?", req.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if req.InputMask == nil {
		req.InputMask = protoutil.AllTrueCommonAgentMask
	}

	updates := make(map[string]interface{})
	if req.InputMask.CertNotAfter {
		updates["expires_at"] = time.Unix(req.CertNotAfter, 0)
	}
	if req.InputMask.CertSerialNumber {
		updates["serial_number"] = req.CertSerialNumber
	}
	if req.InputMask.NewCertNotAfter {
		updates["new_expires_at"] = nullableUnixTimeToDBTime(req.NewCertNotAfter)
	}
	if req.InputMask.NewCertSerialNumber {
		updates["new_serial_number"] = req.NewCertSerialNumber
	}

	if err := tx.Model(&model).Updates(updates).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.UpdateAttestedNodeResponse{
		Node: modelToAttestedNode(model),
	}, nil
}

func deleteAttestedNode(tx *gorm.DB, req *datastore.DeleteAttestedNodeRequest) (*datastore.DeleteAttestedNodeResponse, error) {
	var model AttestedNode
	if err := tx.Find(&model, "spiffe_id = ?", req.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.DeleteAttestedNodeResponse{
		Node: modelToAttestedNode(model),
	}, nil
}

func setNodeSelectors(tx *gorm.DB, req *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	// Previously the deletion of the previous set of node selectors was
	// implemented via query like DELETE FROM node_resolver_map_entries WHERE
	// spiffe_id = ?, but unfortunately this triggered some pessimistic gap
	// locks on the index even when there were no rows matching the WHERE
	// clause (i.e. rows for that spiffe_id). The gap locks caused MySQL
	// deadlocks when SetNodeSelectors was being called concurrently. Changing
	// the transaction isolation level fixed the deadlocks but only when there
	// were no existing rows; the deadlocks still occurred when existing rows
	// existed (i.e. reattestation). Instead, gather all of the IDs to be
	// deleted and delete them from separate queries, which does not trigger
	// gap locks on the index.
	var ids []int64
	if err := tx.Model(&NodeSelector{}).Where("spiffe_id = ?", req.Selectors.SpiffeId).Pluck("id", &ids).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}
	if len(ids) > 0 {
		if err := tx.Where("id IN (?)", ids).Delete(&NodeSelector{}).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	for _, selector := range req.Selectors.Selectors {
		model := &NodeSelector{
			SpiffeID: req.Selectors.SpiffeId,
			Type:     selector.Type,
			Value:    selector.Value,
		}
		if err := tx.Create(model).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	return &datastore.SetNodeSelectorsResponse{}, nil
}

func getNodeSelectors(ctx context.Context, db *sqlDB, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	query := maybeRebind(db.databaseType, "SELECT type, value FROM node_resolver_map_entries WHERE spiffe_id=? ORDER BY id")
	rows, err := db.QueryContext(ctx, query, req.SpiffeId)
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

	return &datastore.GetNodeSelectorsResponse{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  req.SpiffeId,
			Selectors: selectors,
		},
	}, nil
}

func listNodeSelectors(ctx context.Context, db *sqlDB, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	rawQuery, args := buildListNodeSelectorsQuery(req)
	query := maybeRebind(db.databaseType, rawQuery)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	resp := new(datastore.ListNodeSelectorsResponse)

	var currentID string
	var selectors []*common.Selector
	if req.Pagination != nil {
		selectors = make([]*common.Selector, 0, req.Pagination.PageSize)
	} else {
		selectors = make([]*common.Selector, 0, 64)
	}

	push := func(spiffeID string, selector *common.Selector) {
		switch {
		case currentID == "":
			currentID = spiffeID
		case spiffeID != currentID:
			resp.Selectors = append(resp.Selectors, &datastore.NodeSelectors{
				SpiffeId:  currentID,
				Selectors: selectors,
			})
			currentID = spiffeID
			selectors = nil
		}
		selectors = append(selectors, selector)
	}

	var lastID uint64
	var selector *common.Selector
	for rows.Next() {
		var nsRow nodeSelectorRow
		if err := scanNodeSelectorRow(rows, &nsRow); err != nil {
			return nil, err
		}

		var spiffeID string
		if nsRow.SpiffeID.Valid {
			spiffeID = nsRow.SpiffeID.String
		}

		selector = new(common.Selector)
		fillNodeSelectorFromRow(selector, &nsRow)
		push(spiffeID, selector)
		lastID = nsRow.EId
	}

	push("", nil)

	if err := rows.Err(); err != nil {
		return nil, sqlError.Wrap(err)
	}

	if req.Pagination != nil {
		var token string
		if len(resp.Selectors) > 0 {
			token = strconv.FormatUint(lastID, 10)
		}
		resp.Pagination = &datastore.Pagination{
			PageSize: req.Pagination.PageSize,
			Token:    token,
		}
	}

	return resp, nil
}

func buildListNodeSelectorsQuery(req *datastore.ListNodeSelectorsRequest) (query string, args []interface{}) {
	var sb strings.Builder
	var hasWhereClause bool
	sb.WriteString("SELECT nre.id, nre.spiffe_id, nre.type, nre.value FROM node_resolver_map_entries nre")
	if req.ValidAt != nil {
		sb.WriteString(" INNER JOIN attested_node_entries ane ON nre.spiffe_id=ane.spiffe_id WHERE ane.expires_at > ?")
		args = append(args, time.Unix(req.ValidAt.Seconds, 0))
		hasWhereClause = true
	}
	if req.Pagination != nil && req.Pagination.Token != "" {
		sqlKeyword := "WHERE"
		if hasWhereClause {
			sqlKeyword = "AND"
		}

		sb.WriteRune(' ')
		sb.WriteString(sqlKeyword)
		sb.WriteString(" nre.id > ?")
		args = append(args, req.Pagination.Token)
	}

	sb.WriteString(" ORDER BY nre.id ASC")

	if req.Pagination != nil {
		sb.WriteString(" LIMIT ")
		pageSize := strconv.FormatInt(int64(req.Pagination.PageSize), 10)
		sb.WriteString(pageSize)
	}

	return sb.String(), args
}

func createRegistrationEntry(tx *gorm.DB, req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {
	entryID, err := newRegistrationEntryID()
	if err != nil {
		return nil, err
	}

	newRegisteredEntry := RegisteredEntry{
		EntryID:    entryID,
		SpiffeID:   req.Entry.SpiffeId,
		ParentID:   req.Entry.ParentId,
		TTL:        req.Entry.Ttl,
		Admin:      req.Entry.Admin,
		Downstream: req.Entry.Downstream,
		Expiry:     req.Entry.EntryExpiry,
	}

	if err := tx.Create(&newRegisteredEntry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	federatesWith, err := makeFederatesWith(tx, req.Entry.FederatesWith)
	if err != nil {
		return nil, err
	}

	if err := tx.Model(&newRegisteredEntry).Association("FederatesWith").Append(federatesWith).Error; err != nil {
		return nil, err
	}

	for _, registeredSelector := range req.Entry.Selectors {
		newSelector := Selector{
			RegisteredEntryID: newRegisteredEntry.ID,
			Type:              registeredSelector.Type,
			Value:             registeredSelector.Value}

		if err := tx.Create(&newSelector).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	for _, registeredDNS := range req.Entry.DnsNames {
		newDNS := DNSName{
			RegisteredEntryID: newRegisteredEntry.ID,
			Value:             registeredDNS,
		}

		if err := tx.Create(&newDNS).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	entry, err := modelToEntry(tx, newRegisteredEntry)
	if err != nil {
		return nil, err
	}

	return &datastore.CreateRegistrationEntryResponse{
		Entry: entry,
	}, nil
}

func fetchRegistrationEntry(ctx context.Context, db *sqlDB, req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	query, args, err := buildFetchRegistrationEntryQuery(db.databaseType, db.supportsCTE, req)
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

	return &datastore.FetchRegistrationEntryResponse{
		Entry: entry,
	}, nil
}

func buildFetchRegistrationEntryQuery(dbType string, supportsCTE bool, req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
	switch dbType {
	case SQLite:
		// The SQLite3 queries unconditionally leverage CTE since the
		// embedded version of SQLite3 supports CTE.
		return buildFetchRegistrationEntryQuerySQLite3(req)
	case PostgreSQL:
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		return buildFetchRegistrationEntryQueryPostgreSQL(req)
	case MySQL:
		if supportsCTE {
			return buildFetchRegistrationEntryQueryMySQLCTE(req)
		}
		return buildFetchRegistrationEntryQueryMySQL(req)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildFetchRegistrationEntryQuerySQLite3(req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = ?
)
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []interface{}{req.EntryId}, nil
}

func buildFetchRegistrationEntryQueryPostgreSQL(req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = $1
)
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []interface{}{req.EntryId}, nil
}

func buildFetchRegistrationEntryQueryMySQL(req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
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
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
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
	return query, []interface{}{req.EntryId}, nil
}

func buildFetchRegistrationEntryQueryMySQLCTE(req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
	const query = `
WITH listing AS (
	SELECT id FROM registered_entries WHERE entry_id = ?
)
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY selector_id, dns_name_id
;`
	return query, []interface{}{req.EntryId}, nil
}

func countRegistrationEntries(tx *gorm.DB) (*datastore.CountRegistrationEntriesResponse, error) {
	var count int
	if err := tx.Model(&RegisteredEntry{}).Count(&count).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.CountRegistrationEntriesResponse{
		Entries: int32(count),
	}
	return resp, nil
}

func listRegistrationEntries(ctx context.Context, db *sqlDB, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
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
		resp, err := listRegistrationEntriesOnce(ctx, db, req)
		if err != nil {
			return nil, err
		}

		if req.BySelectors == nil || len(resp.Entries) == 0 {
			return resp, nil
		}

		resp.Entries = filterEntriesBySelectorSet(resp.Entries, req.BySelectors.Selectors)
		if len(resp.Entries) > 0 || resp.Pagination == nil || len(resp.Pagination.Token) == 0 {
			return resp, nil
		}

		req.Pagination = resp.Pagination
	}
}

func filterEntriesBySelectorSet(entries []*common.RegistrationEntry, selectors []*common.Selector) []*common.RegistrationEntry {
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

func listRegistrationEntriesOnce(ctx context.Context, db *sqlDB, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	query, args, err := buildListRegistrationEntriesQuery(db.databaseType, db.supportsCTE, req)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}
	defer rows.Close()

	var entries []*common.RegistrationEntry
	if req.Pagination != nil {
		entries = make([]*common.RegistrationEntry, 0, req.Pagination.PageSize)
	} else {
		// start the slice off with a little capacity to avoid the first few
		// reallocations
		entries = make([]*common.RegistrationEntry, 0, 64)
	}

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

func buildListRegistrationEntriesQuery(dbType string, supportsCTE bool, req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
	switch dbType {
	case SQLite:
		// The SQLite3 queries unconditionally leverage CTE since the
		// embedded version of SQLite3 supports CTE.
		return buildListRegistrationEntriesQuerySQLite3(req)
	case PostgreSQL:
		// The PostgreSQL queries unconditionally leverage CTE since all versions
		// of PostgreSQL supported by the plugin support CTE.
		return buildListRegistrationEntriesQueryPostgreSQL(req)
	case MySQL:
		if supportsCTE {
			return buildListRegistrationEntriesQueryMySQLCTE(req)
		}
		return buildListRegistrationEntriesQueryMySQL(req)
	default:
		return "", nil, sqlError.New("unsupported db type: %q", dbType)
	}
}

func buildListRegistrationEntriesQuerySQLite3(req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
	builder := new(strings.Builder)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, SQLite, req)
	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return builder.String(), args, nil
}

func buildListRegistrationEntriesQueryPostgreSQL(req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
	builder := new(strings.Builder)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, PostgreSQL, req)
	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return postgreSQLRebind(builder.String()), args, nil
}

func maybeRebind(dbType, query string) string {
	if dbType == PostgreSQL {
		return postgreSQLRebind(query)
	}
	return query
}

func postgreSQLRebind(s string) string {
	return bindVarsFn(func(n int) string {
		return "$" + strconv.Itoa(n)
	}, s)
}

func buildListRegistrationEntriesQueryMySQL(req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
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
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
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
	if err != nil {
		return "", nil, err
	}

	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString("\nORDER BY e_id, selector_id, dns_name_id\n;")

	return builder.String(), args, nil
}

func buildListRegistrationEntriesQueryMySQLCTE(req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
	builder := new(strings.Builder)

	filtered, args, err := appendListRegistrationEntriesFilterQuery("\nWITH listing AS (\n", builder, MySQL, req)
	if err != nil {
		return "", nil, err
	}
	if filtered {
		builder.WriteString(")")
	}

	builder.WriteString(`
SELECT
	id as e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
`)
	if filtered {
		builder.WriteString("WHERE\n\tF.registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
ORDER BY e_id, selector_id, dns_name_id
;`)

	return builder.String(), args, nil
}

type idFilterNode struct {
	// mutually exclusive with children
	query string

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
	if n.query != "" {
		if bol {
			indent(builder, indentation)
		}
		builder.WriteString(n.query)
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
		builder.WriteString("SELECT id FROM (\n")
		for i, child := range n.children {
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("UNION\n")
			}
			child.render(builder, dbType, i, indentation+1, true, true)
		}
	case dbType != MySQL:
		builder.WriteString("SELECT id FROM (\n")
		for i, child := range n.children {
			if i > 0 {
				indent(builder, indentation+1)
				builder.WriteString("INTERSECT\n")
			}
			child.render(builder, dbType, i, indentation+1, true, true)
		}
	default:
		needsName = false
		builder.WriteString("SELECT DISTINCT id FROM (\n")
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
				builder.WriteString("USING(id)\n")
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

func appendListRegistrationEntriesFilterQuery(filterExp string, builder *strings.Builder, dbType string, req *datastore.ListRegistrationEntriesRequest) (bool, []interface{}, error) {
	var args []interface{}

	var root idFilterNode

	if req.ByParentId != nil || req.BySpiffeId != nil {
		subquery := new(strings.Builder)
		subquery.WriteString("SELECT id FROM registered_entries WHERE ")
		if req.ByParentId != nil {
			subquery.WriteString("parent_id = ?")
			args = append(args, req.ByParentId.Value)
		}
		if req.BySpiffeId != nil {
			if req.ByParentId != nil {
				subquery.WriteString(" AND ")
			}
			subquery.WriteString("spiffe_id = ?")
			args = append(args, req.BySpiffeId.Value)
		}
		root.children = append(root.children, idFilterNode{
			query: subquery.String(),
		})
	}

	if req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
		switch req.BySelectors.Match {
		case datastore.BySelectors_MATCH_SUBSET:
			// subset needs a union, so we need to group them and add the group
			// as a child to the root.
			group := idFilterNode{
				union: true,
			}
			for range req.BySelectors.Selectors {
				group.children = append(group.children, idFilterNode{
					query: "SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?",
				})
			}
			root.children = append(root.children, group)
		case datastore.BySelectors_MATCH_EXACT:
			// exact match does uses an intersection, so we can just add these
			// directly to the root idFilterNode, since it is already an intersection
			for range req.BySelectors.Selectors {
				root.children = append(root.children, idFilterNode{
					query: "SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?",
				})
			}
		default:
			return false, nil, errs.New("unhandled match behavior %q", req.BySelectors.Match)
		}
		for _, selector := range req.BySelectors.Selectors {
			args = append(args, selector.Type, selector.Value)
		}
	}

	filtered := false
	filter := func() {
		if !filtered {
			builder.WriteString(filterExp)
		}
		filtered = true
	}

	indentation := 1
	if req.Pagination != nil && dbType == MySQL {
		filter()
		builder.WriteString("\tSELECT id FROM (\n")
		indentation = 2
	}

	if len(root.children) > 0 {
		filter()
		root.Render(builder, dbType, indentation, req.Pagination == nil)
	}

	if req.Pagination != nil {
		filter()
		if len(root.children) == 0 {
			indent(builder, indentation)
			builder.WriteString("SELECT id FROM registered_entries")
		}
		if len(req.Pagination.Token) > 0 {
			token, err := strconv.ParseUint(req.Pagination.Token, 10, 32)
			if err != nil {
				return false, nil, status.Errorf(codes.InvalidArgument, "could not parse token '%v'", req.Pagination.Token)
			}
			if len(root.children) == 1 {
				builder.WriteString(" AND id > ?")
			} else {
				builder.WriteString(" WHERE id > ?")
			}
			args = append(args, token)
		}
		builder.WriteString(" ORDER BY id ASC LIMIT ")
		builder.WriteString(strconv.FormatInt(int64(req.Pagination.PageSize), 10))
		builder.WriteString("\n")

		if dbType == MySQL {
			builder.WriteString("\t) workaround_for_mysql_subquery_limit\n")
		}
	}

	return filtered, args, nil
}

type nodeRow struct {
	EId             uint64
	SpiffeID        string
	DataType        sql.NullString
	SerialNumber    sql.NullString
	ExpiresAt       sql.NullTime
	NewSerialNumber sql.NullString
	NewExpiresAt    sql.NullTime
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

	return nil
}

type nodeSelectorRow struct {
	EId      uint64
	SpiffeID sql.NullString
	Type     sql.NullString
	Value    sql.NullString
}

func scanNodeSelectorRow(rs *sql.Rows, r *nodeSelectorRow) error {
	return sqlError.Wrap(rs.Scan(
		&r.EId,
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
	TrustDomain    sql.NullString
	DNSNameID      sql.NullInt64
	DNSName        sql.NullString
	RevisionNumber sql.NullInt64
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
		&r.SelectorID,
		&r.SelectorType,
		&r.SelectorValue,
		&r.TrustDomain,
		&r.DNSNameID,
		&r.DNSName,
		&r.RevisionNumber,
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
	if r.RegTTL.Valid {
		entry.Ttl = int32(r.RegTTL.Int64)
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

func updateRegistrationEntry(tx *gorm.DB,
	req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	if err := validateRegistrationEntryForUpdate(req.Entry, req.Mask); err != nil {
		return nil, err
	}

	// Get the existing entry
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", req.Entry.EntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}
	if req.Mask == nil || req.Mask.Selectors {
		// Delete existing selectors - we will write new ones
		if err := tx.Exec("DELETE FROM selectors WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		selectors := []Selector{}
		for _, s := range req.Entry.Selectors {
			selector := Selector{
				Type:  s.Type,
				Value: s.Value,
			}

			selectors = append(selectors, selector)
		}
		entry.Selectors = selectors
	}

	if req.Mask == nil || req.Mask.DnsNames {
		// Delete existing DNSs - we will write new ones
		if err := tx.Exec("DELETE FROM dns_names WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		dnsList := []DNSName{}
		for _, d := range req.Entry.DnsNames {
			dns := DNSName{
				Value: d,
			}

			dnsList = append(dnsList, dns)
		}
		entry.DNSList = dnsList
	}

	if req.Mask == nil || req.Mask.SpiffeId {
		entry.SpiffeID = req.Entry.SpiffeId
	}
	if req.Mask == nil || req.Mask.ParentId {
		entry.ParentID = req.Entry.ParentId
	}
	if req.Mask == nil || req.Mask.Ttl {
		entry.TTL = req.Entry.Ttl
	}
	if req.Mask == nil || req.Mask.Admin {
		entry.Admin = req.Entry.Admin
	}
	if req.Mask == nil || req.Mask.Downstream {
		entry.Downstream = req.Entry.Downstream
	}
	if req.Mask == nil || req.Mask.EntryExpiry {
		entry.Expiry = req.Entry.EntryExpiry
	}

	// Revision number is increased by 1 on every update call
	entry.RevisionNumber++

	if err := tx.Save(&entry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if req.Mask == nil || req.Mask.FederatesWith {
		federatesWith, err := makeFederatesWith(tx, req.Entry.FederatesWith)
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

	return &datastore.UpdateRegistrationEntryResponse{
		Entry: returnEntry,
	}, nil
}

func deleteRegistrationEntry(tx *gorm.DB, req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", req.EntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	respEntry, err := modelToEntry(tx, entry)
	if err != nil {
		return nil, err
	}

	err = deleteRegistrationEntrySupport(tx, entry)
	if err != nil {
		return nil, err
	}

	return &datastore.DeleteRegistrationEntryResponse{
		Entry: respEntry,
	}, nil
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

	return nil
}

func pruneRegistrationEntries(tx *gorm.DB, req *datastore.PruneRegistrationEntriesRequest) (*datastore.PruneRegistrationEntriesResponse, error) {
	var registrationEntries []RegisteredEntry
	if err := tx.Where("expiry != 0").Where("expiry < ?", req.ExpiresBefore).Find(&registrationEntries).Error; err != nil {
		return nil, err
	}

	for _, entry := range registrationEntries {
		if err := deleteRegistrationEntrySupport(tx, entry); err != nil {
			return nil, err
		}
	}

	return &datastore.PruneRegistrationEntriesResponse{}, nil
}

func createJoinToken(tx *gorm.DB, req *datastore.CreateJoinTokenRequest) (*datastore.CreateJoinTokenResponse, error) {
	t := JoinToken{
		Token:  req.JoinToken.Token,
		Expiry: req.JoinToken.Expiry,
	}

	if err := tx.Create(&t).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.CreateJoinTokenResponse{
		JoinToken: req.JoinToken,
	}, nil
}

func fetchJoinToken(tx *gorm.DB, req *datastore.FetchJoinTokenRequest) (*datastore.FetchJoinTokenResponse, error) {
	var model JoinToken
	err := tx.Find(&model, "token = ?", req.Token).Error
	if err == gorm.ErrRecordNotFound {
		return &datastore.FetchJoinTokenResponse{}, nil
	} else if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.FetchJoinTokenResponse{
		JoinToken: modelToJoinToken(model),
	}, nil
}

func deleteJoinToken(tx *gorm.DB, req *datastore.DeleteJoinTokenRequest) (*datastore.DeleteJoinTokenResponse, error) {
	var model JoinToken
	if err := tx.Find(&model, "token = ?", req.Token).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.DeleteJoinTokenResponse{
		JoinToken: modelToJoinToken(model),
	}, nil
}

func pruneJoinTokens(tx *gorm.DB, req *datastore.PruneJoinTokensRequest) (*datastore.PruneJoinTokensResponse, error) {
	if err := tx.Where("expiry < ?", req.ExpiresBefore).Delete(&JoinToken{}).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.PruneJoinTokensResponse{}, nil
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
		return sqlError.New("invalid request: missing registered entry")
	}

	if entry.Selectors == nil || len(entry.Selectors) == 0 {
		return sqlError.New("invalid registration entry: missing selector list")
	}

	if len(entry.SpiffeId) == 0 {
		return sqlError.New("invalid registration entry: missing SPIFFE ID")
	}

	if entry.Ttl < 0 {
		return sqlError.New("invalid registration entry: TTL is not set")
	}

	return nil
}

func validateRegistrationEntryForUpdate(entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) error {
	if entry == nil {
		return sqlError.New("invalid request: missing registered entry")
	}

	if (mask == nil || mask.Selectors) &&
		(entry.Selectors == nil || len(entry.Selectors) == 0) {
		return sqlError.New("invalid registration entry: missing selector list")
	}

	if (mask == nil || mask.SpiffeId) &&
		entry.SpiffeId == "" {
		return sqlError.New("invalid registration entry: missing SPIFFE ID")
	}

	if (mask == nil || mask.Ttl) &&
		(entry.Ttl < 0) {
		return sqlError.New("invalid registration entry: TTL is not set")
	}

	return nil
}

// bundleToModel converts the given Protobuf bundle message to a database model. It
// performs validation, and fully parses certificates to form CACert embedded models.
func bundleToModel(pb *common.Bundle) (*Bundle, error) {
	if pb == nil {
		return nil, sqlError.New("missing bundle in request")
	}
	id, err := idutil.NormalizeSpiffeID(pb.TrustDomainId, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	data, err := proto.Marshal(pb)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &Bundle{
		TrustDomain: id,
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
		Ttl:            model.TTL,
		FederatesWith:  federatesWith,
		Admin:          model.Admin,
		Downstream:     model.Downstream,
		EntryExpiry:    model.Expiry,
		DnsNames:       dnsList,
		RevisionNumber: model.RevisionNumber,
	}, nil
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
	}
}

func modelToJoinToken(model JoinToken) *datastore.JoinToken {
	return &datastore.JoinToken{
		Token:  model.Token,
		Expiry: model.Expiry,
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
	if cfg.DatabaseType == "" {
		return errors.New("database_type must be set")
	}

	if cfg.ConnectionString == "" {
		return errors.New("connection_string must be set")
	}

	if cfg.DatabaseType == MySQL {
		if err := validateMySQLConfig(cfg, false); err != nil {
			return err
		}

		if cfg.RoConnectionString != "" {
			if err := validateMySQLConfig(cfg, true); err != nil {
				return err
			}
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
