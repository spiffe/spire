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

	// gorm sqlite dialect init registration
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	ds_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/hostservices"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/datastore"
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

func builtin(p *SQLPlugin) catalog.Plugin {
	return catalog.MakePlugin("sql",
		datastore.PluginServer(p),
	)
}

// Configuration for the datastore.
// Pointer values are used to distinguish between "unset" and "zero" values.
type configuration struct {
	DatabaseType     string  `hcl:"database_type" json:"database_type"`
	ConnectionString string  `hcl:"connection_string" json:"connection_string"`
	RootCAPath       string  `hcl:"root_ca_path" json:"root_ca_path"`
	ClientCertPath   string  `hcl:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath    string  `hcl:"client_key_path" json:"client_key_path"`
	ConnMaxLifetime  *string `hcl:"conn_max_lifetime" json:"conn_max_lifetime"`
	MaxOpenConns     *int    `hcl:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns     *int    `hcl:"max_idle_conns" json:"max_idle_conns"`
	DisableMigration bool    `hcl:"disable_migration" json:"disable_migration"`

	// Undocumented flags
	LogSQL bool `hcl:"log_sql" json:"log_sql"`
}

type sqlDB struct {
	databaseType     string
	connectionString string
	raw              *sql.DB
	*gorm.DB

	// this lock is only required for synchronized writes with "sqlite3". see
	// the withTx() implementation for details.
	opMu sync.Mutex
}

// SQLPlugin plugin for SQL connection and operations
type SQLPlugin struct {
	mu             sync.Mutex
	db             *sqlDB
	log            hclog.Logger
	metricsService hostservices.MetricsService
}

// New creates a new sql plugin struct. Configure must be called
// in order to start the db.
func New() *SQLPlugin {
	return &SQLPlugin{}
}

func (ds *SQLPlugin) SetLogger(logger hclog.Logger) {
	ds.log = logger
}

func (p *SQLPlugin) BrokerHostServices(broker catalog.HostServiceBroker) error {
	has, err := broker.GetHostService(hostservices.MetricsServiceHostServiceClient(&p.metricsService))
	if err != nil {
		return err
	}
	if !has {
		return errors.New("Metrics host service is required")
	}
	return nil
}

// CreateBundle stores the given bundle
func (ds *SQLPlugin) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (resp *datastore.CreateBundleResponse, err error) {
	callCounter := ds_telemetry.StartCreateBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (resp *datastore.UpdateBundleResponse, err error) {
	callCounter := ds_telemetry.StartUpdateBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *SQLPlugin) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (resp *datastore.SetBundleResponse, err error) {
	callCounter := ds_telemetry.StartSetBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = setBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *SQLPlugin) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (resp *datastore.AppendBundleResponse, err error) {
	callCounter := ds_telemetry.StartAppendBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = appendBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *SQLPlugin) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (resp *datastore.DeleteBundleResponse, err error) {
	callCounter := ds_telemetry.StartDeleteBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *SQLPlugin) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (resp *datastore.FetchBundleResponse, err error) {
	callCounter := ds_telemetry.StartFetchBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *SQLPlugin) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (resp *datastore.ListBundlesResponse, err error) {
	callCounter := ds_telemetry.StartListBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listBundles(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneBundle removes expired certs and keys from a bundle
func (ds *SQLPlugin) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (resp *datastore.PruneBundleResponse, err error) {
	callCounter := ds_telemetry.StartPruneBundleCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteRepeatableReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneBundle(tx, req, ds.log)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// CreateAttestedNode stores the given attested node
func (ds *SQLPlugin) CreateAttestedNode(ctx context.Context,
	req *datastore.CreateAttestedNodeRequest) (resp *datastore.CreateAttestedNodeResponse, err error) {
	callCounter := ds_telemetry.StartCreateNodeCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) FetchAttestedNode(ctx context.Context,
	req *datastore.FetchAttestedNodeRequest) (resp *datastore.FetchAttestedNodeResponse, err error) {
	callCounter := ds_telemetry.StartFetchNodeCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListAttestedNodes lists all attested nodes (pagination available)
func (ds *SQLPlugin) ListAttestedNodes(ctx context.Context,
	req *datastore.ListAttestedNodesRequest) (resp *datastore.ListAttestedNodesResponse, err error) {
	callCounter := ds_telemetry.StartListNodeCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodes(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateAttestedNode updates the given node's cert serial and expiration.
func (ds *SQLPlugin) UpdateAttestedNode(ctx context.Context,
	req *datastore.UpdateAttestedNodeRequest) (resp *datastore.UpdateAttestedNodeResponse, err error) {
	callCounter := ds_telemetry.StartUpdateNodeCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteAttestedNode deletes the given attested node
func (ds *SQLPlugin) DeleteAttestedNode(ctx context.Context,
	req *datastore.DeleteAttestedNodeRequest) (resp *datastore.DeleteAttestedNodeResponse, err error) {
	callCounter := ds_telemetry.StartDeleteNodeCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// SetNodeSelectors sets node (agent) selectors by SPIFFE ID, deleting old selectors first
func (ds *SQLPlugin) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (resp *datastore.SetNodeSelectorsResponse, err error) {
	callCounter := ds_telemetry.StartSetNodeSelectorsCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) GetNodeSelectors(ctx context.Context,
	req *datastore.GetNodeSelectorsRequest) (resp *datastore.GetNodeSelectorsResponse, err error) {
	callCounter := ds_telemetry.StartGetNodeSelectorsCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	return getNodeSelectors(ctx, ds.db.databaseType, ds.db.raw, req)
}

// CreateRegistrationEntry stores the given registration entry
func (ds *SQLPlugin) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (resp *datastore.CreateRegistrationEntryResponse, err error) {
	callCounter := ds_telemetry.StartCreateRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) FetchRegistrationEntry(ctx context.Context,
	req *datastore.FetchRegistrationEntryRequest) (resp *datastore.FetchRegistrationEntryResponse, err error) {
	callCounter := ds_telemetry.StartFetchRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	return fetchRegistrationEntry(ctx, ds.db.databaseType, ds.db.raw, req)
}

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *SQLPlugin) ListRegistrationEntries(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest) (resp *datastore.ListRegistrationEntriesResponse, err error) {
	callCounter := ds_telemetry.StartListRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	return listRegistrationEntries(ctx, ds.db.databaseType, ds.db.raw, req)
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *SQLPlugin) UpdateRegistrationEntry(ctx context.Context,
	req *datastore.UpdateRegistrationEntryRequest) (resp *datastore.UpdateRegistrationEntryResponse, err error) {
	callCounter := ds_telemetry.StartUpdateRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = validateRegistrationEntry(req.Entry); err != nil {
		return nil, err
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteRegistrationEntry deletes the given registration
func (ds *SQLPlugin) DeleteRegistrationEntry(ctx context.Context,
	req *datastore.DeleteRegistrationEntryRequest) (resp *datastore.DeleteRegistrationEntryResponse, err error) {
	callCounter := ds_telemetry.StartDeleteRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (resp *datastore.PruneRegistrationEntriesResponse, err error) {
	callCounter := ds_telemetry.StartPruneRegistrationCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneRegistrationEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateJoinToken takes a Token message and stores it
func (ds *SQLPlugin) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (resp *datastore.CreateJoinTokenResponse, err error) {
	callCounter := ds_telemetry.StartCreateJoinTokenCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (resp *datastore.FetchJoinTokenResponse, err error) {
	callCounter := ds_telemetry.StartFetchJoinTokenCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteJoinToken deletes the given join token
func (ds *SQLPlugin) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (resp *datastore.DeleteJoinTokenResponse, err error) {
	callCounter := ds_telemetry.StartDeleteJoinTokenCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

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
func (ds *SQLPlugin) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (resp *datastore.PruneJoinTokensResponse, err error) {
	callCounter := ds_telemetry.StartPruneJoinTokenCall(ds.prepareMetricsForCall(ctx))
	defer callCounter.Done(&err)

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneJoinTokens(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// Configure parses HCL config payload into config struct, and opens new DB based on the result
func (ds *SQLPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &configuration{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.db == nil ||
		config.ConnectionString != ds.db.connectionString ||
		config.DatabaseType != ds.db.databaseType {

		db, err := ds.openDB(config)
		if err != nil {
			return nil, err
		}

		if ds.db != nil {
			ds.db.Close()
		}

		raw := db.DB()
		if raw == nil {
			return nil, sqlError.New("unable to get raw database object")
		}

		ds.db = &sqlDB{
			DB:               db,
			raw:              raw,
			databaseType:     config.DatabaseType,
			connectionString: config.ConnectionString,
		}
	}

	ds.db.LogMode(config.LogSQL)

	return &spi.ConfigureResponse{}, nil
}

func (p *SQLPlugin) closeDB() {
	if p.db != nil {
		p.db.Close()
	}
}

// GetPluginInfo returns the sql plugin
func (*SQLPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (ds *SQLPlugin) withWriteRepeatableReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
}

func (ds *SQLPlugin) withWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false, nil)
}

func (ds *SQLPlugin) withReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, true, nil)
}

func (ds *SQLPlugin) withTx(ctx context.Context, op func(tx *gorm.DB) error, readOnly bool, opts *sql.TxOptions) error {
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
		return gormToGRPCStatus(err)
	}

	if readOnly {
		// rolling back makes sure that functions that are invoked with
		// withReadTx, and then do writes, will not pass unit tests, since the
		// writes won't be committed.
		return sqlError.Wrap(tx.Rollback().Error)
	}
	return sqlError.Wrap(tx.Commit().Error)
}

func (ds *SQLPlugin) openDB(cfg *configuration) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	ds.log.Info("Opening SQL database", telemetry.DatabaseType, cfg.DatabaseType)
	switch cfg.DatabaseType {
	case SQLite:
		db, err = sqlite{}.connect(cfg)
	case PostgreSQL:
		db, err = postgres{}.connect(cfg)
	case MySQL:
		db, err = mysql{}.connect(cfg)
	default:
		return nil, sqlError.New("unsupported database_type: %v", cfg.DatabaseType)
	}
	if err != nil {
		return nil, err
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
			return nil, fmt.Errorf("failed to parse conn_max_lifetime %q: %v", *cfg.ConnMaxLifetime, err)
		}
		db.DB().SetConnMaxLifetime(connMaxLifetime)
	}

	if err := migrateDB(db, cfg.DatabaseType, cfg.DisableMigration, ds.log); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func (ds *SQLPlugin) prepareMetricsForCall(ctx context.Context) telemetry.Metrics {
	return metricsservice.WrapPluginMetricsForContext(ctx, ds.metricsService, ds.log)
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
	newModel, err := bundleToModel(req.Bundle)
	if err != nil {
		return nil, err
	}

	model := &Bundle{}
	if err := tx.Find(model, "trust_domain = ?", newModel.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	model.Data = newModel.Data
	if err := tx.Save(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.UpdateBundleResponse{
		Bundle: req.Bundle,
	}, nil
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
	model := new(Bundle)
	if err := tx.Find(model, "trust_domain = ?", req.TrustDomainId).Error; err != nil {
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
			return nil, sqlError.New("cannot delete bundle; federated with %d registration entries", entriesCount)
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
	model := new(Bundle)
	err := tx.Find(model, "trust_domain = ?", req.TrustDomainId).Error
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

// ListBundles can be used to fetch all existing bundles.
func listBundles(tx *gorm.DB, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	var bundles []Bundle
	if err := tx.Find(&bundles).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.ListBundlesResponse{}
	for _, model := range bundles {
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
		SpiffeID:     req.Node.SpiffeId,
		DataType:     req.Node.AttestationDataType,
		SerialNumber: req.Node.CertSerialNumber,
		ExpiresAt:    time.Unix(req.Node.CertNotAfter, 0),
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

func listAttestedNodes(tx *gorm.DB, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	p := req.Pagination
	var err error
	if p != nil {
		tx, err = applyPagination(p, tx)
		if err != nil {
			return nil, err
		}
	}

	if req.ByExpiresBefore != nil {
		tx = tx.Where("expires_at < ?", time.Unix(req.ByExpiresBefore.Value, 0))
	}

	var models []AttestedNode
	if err := tx.Find(&models).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if p != nil {
		p.Token = ""
		if len(models) > 0 {
			lastEntry := models[len(models)-1]
			p.Token = fmt.Sprint(lastEntry.ID)
		}
	}

	resp := &datastore.ListAttestedNodesResponse{
		Nodes:      make([]*common.AttestedNode, 0, len(models)),
		Pagination: p,
	}

	for _, model := range models {
		resp.Nodes = append(resp.Nodes, modelToAttestedNode(model))
	}
	return resp, nil
}

func updateAttestedNode(tx *gorm.DB, req *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	var model AttestedNode
	if err := tx.Find(&model, "spiffe_id = ?", req.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	updates := AttestedNode{
		SerialNumber: req.CertSerialNumber,
		ExpiresAt:    time.Unix(req.CertNotAfter, 0),
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
	if err := tx.Delete(NodeSelector{}, "spiffe_id = ?", req.Selectors.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
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

func getNodeSelectors(ctx context.Context, dbType string, db *sql.DB, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	query := maybeRebind(dbType, "SELECT type, value FROM node_resolver_map_entries WHERE spiffe_id=? ORDER BY id")
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

func createRegistrationEntry(tx *gorm.DB,
	req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

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

func fetchRegistrationEntry(ctx context.Context, dbType string, db *sql.DB, req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	query, args, err := buildFetchRegistrationEntryQuery(dbType, req)
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

func buildFetchRegistrationEntryQuery(dbType string, req *datastore.FetchRegistrationEntryRequest) (string, []interface{}, error) {
	switch dbType {
	case SQLite:
		return buildFetchRegistrationEntryQuerySQLite3(req)
	case PostgreSQL:
		return buildFetchRegistrationEntryQueryPostgreSQL(req)
	case MySQL:
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	D.value AS dns_name
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

func listRegistrationEntries(ctx context.Context, dbType string, db *sql.DB, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
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
		resp, err := listRegistrationEntriesOnce(ctx, dbType, db, req)
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

func listRegistrationEntriesOnce(ctx context.Context, dbType string, db *sql.DB, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	query, args, err := buildListRegistrationEntriesQuery(dbType, req)
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
	var lastEID uint64

	for rows.Next() {
		var r entryRow
		if err := scanEntryRow(rows, &r); err != nil {
			return nil, err
		}

		var entry *common.RegistrationEntry
		if len(entries) == 0 || lastEID != r.EId {
			lastEID = r.EId
			entry = new(common.RegistrationEntry)
			entries = append(entries, entry)
		} else {
			entry = entries[len(entries)-1]
		}

		if err := fillEntryFromRow(entry, &r); err != nil {
			return nil, err
		}
	}

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

func buildListRegistrationEntriesQuery(dbType string, req *datastore.ListRegistrationEntriesRequest) (string, []interface{}, error) {
	switch dbType {
	case SQLite:
		return buildListRegistrationEntriesQuerySQLite3(req)
	case PostgreSQL:
		return buildListRegistrationEntriesQueryPostgreSQL(req)
	case MySQL:
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
	NULL AS dns_name
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	NULL AS dns_name
FROM
	registered_entries
`)
	if filtered {
		builder.WriteString("WHERE id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
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
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
`)
	if filtered {
		builder.WriteString("WHERE registered_entry_id IN (SELECT id FROM listing)\n")
	}
	builder.WriteString(`
UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	D.value AS dns_name
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
			token, err := strconv.ParseUint(string(req.Pagination.Token), 10, 32)
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

type entryRow struct {
	EId           uint64
	EntryID       sql.NullString
	SpiffeID      sql.NullString
	ParentID      sql.NullString
	RegTTL        sql.NullInt64
	Admin         sql.NullBool
	Downstream    sql.NullBool
	Expiry        sql.NullInt64
	SelectorID    sql.NullInt64
	SelectorType  sql.NullString
	SelectorValue sql.NullString
	TrustDomain   sql.NullString
	DNSNameID     sql.NullInt64
	DNSName       sql.NullString
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

// update pagination token based in last result in returned list
func updatePaginationToken(p *datastore.Pagination, entries []RegisteredEntry) {
	if len(entries) == 0 {
		return
	}
	lastEntry := (entries)[len(entries)-1]
	p.Token = fmt.Sprint(lastEntry.ID)
}

func updateRegistrationEntry(tx *gorm.DB,
	req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	// Get the existing entry
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", req.Entry.EntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

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

	entry.SpiffeID = req.Entry.SpiffeId
	entry.ParentID = req.Entry.ParentId
	entry.TTL = req.Entry.Ttl
	entry.Selectors = selectors
	entry.Admin = req.Entry.Admin
	entry.Downstream = req.Entry.Downstream
	entry.Expiry = req.Entry.EntryExpiry
	entry.DNSList = dnsList
	if err := tx.Save(&entry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	federatesWith, err := makeFederatesWith(tx, req.Entry.FederatesWith)
	if err != nil {
		return nil, err
	}

	if err := tx.Model(&entry).Association("FederatesWith").Replace(federatesWith).Error; err != nil {
		return nil, err
	}

	req.Entry.EntryId = entry.EntryID
	return &datastore.UpdateRegistrationEntryResponse{
		Entry: req.Entry,
	}, nil
}

func deleteRegistrationEntry(tx *gorm.DB,
	req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

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

func modelsToEntries(tx *gorm.DB, fetchedRegisteredEntries []RegisteredEntry) (responseEntries []*common.RegistrationEntry, err error) {
	entries, err := modelsToUnsortedEntries(tx, fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func modelsToUnsortedEntries(tx *gorm.DB, fetchedRegisteredEntries []RegisteredEntry) (responseEntries []*common.RegistrationEntry, err error) {
	for _, regEntry := range fetchedRegisteredEntries {
		responseEntry, err := modelToEntry(tx, regEntry)
		if err != nil {
			return nil, err
		}
		responseEntries = append(responseEntries, responseEntry)
	}
	return responseEntries, nil
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
		EntryId:       model.EntryID,
		Selectors:     selectors,
		SpiffeId:      model.SpiffeID,
		ParentId:      model.ParentID,
		Ttl:           model.TTL,
		FederatesWith: federatesWith,
		Admin:         model.Admin,
		Downstream:    model.Downstream,
		EntryExpiry:   model.Expiry,
		DnsNames:      dnsList,
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

	return bindVarsFn(func(n int) string {
		return dialect.BindVar(n)
	}, query)
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

	switch cfg.DatabaseType {
	case MySQL:
		if err := validateMySQLConfig(cfg); err != nil {
			return err
		}
	}

	return nil
}

// gormToGRPCStatus takes an error, and converts it to a GRPC error.  If the
// error is already a gRPC status , it will be returned unmodified. Otherwise
// if the error is a gorm error type with a known mapping to a GRPC status,
// that code will be set, otherwise the code will be set to Unknown.
func gormToGRPCStatus(err error) error {
	unwrapped := errs.Unwrap(err)
	if _, ok := status.FromError(unwrapped); ok {
		return unwrapped
	}

	code := codes.Unknown
	switch {
	case gorm.IsRecordNotFoundError(unwrapped):
		code = codes.NotFound
	default:
	}

	return status.Error(code, err.Error())
}
