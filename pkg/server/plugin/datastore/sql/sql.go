package sql

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/zeebo/errs"
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

type configuration struct {
	DatabaseType     string `hcl:"database_type" json:"database_type"`
	ConnectionString string `hcl:"connection_string" json:"connection_string"`

	// Undocumented flags
	LogSQL bool `hcl:"log_sql" json:"log_sql"`
}

type sqlDB struct {
	databaseType     string
	connectionString string
	*gorm.DB

	// this lock is only required for synchronized writes with "sqlite3". see
	// the withTx() implementation for details.
	opMu sync.Mutex
}

type database interface {
	connect(string) (*gorm.DB, error)
}

type sqlPlugin struct {
	mu sync.Mutex
	db *sqlDB
}

func newPlugin() *sqlPlugin {
	return &sqlPlugin{}
}

// New creates a new sql plugin struct. Configure must be called
// in order to start the db.
func New() datastore.Plugin {
	return newPlugin()
}

// CreateBundle stores the given bundle
func (ds *sqlPlugin) CreateBundle(ctx context.Context, req *datastore.Bundle) (resp *datastore.Bundle, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *sqlPlugin) UpdateBundle(ctx context.Context, req *datastore.Bundle) (resp *datastore.Bundle, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// AppendBundle adds the specified CA certificates to an existing bundle. If no bundle exists for the
// specified trust domain, create one. Returns the entirety.
func (ds *sqlPlugin) AppendBundle(ctx context.Context, req *datastore.Bundle) (resp *datastore.Bundle, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = appendBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *sqlPlugin) DeleteBundle(ctx context.Context, req *datastore.Bundle) (resp *datastore.Bundle, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *sqlPlugin) FetchBundle(ctx context.Context, req *datastore.Bundle) (resp *datastore.Bundle, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *sqlPlugin) ListBundles(ctx context.Context, req *common.Empty) (resp *datastore.Bundles, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listBundles(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) CreateAttestedNodeEntry(ctx context.Context,
	req *datastore.CreateAttestedNodeEntryRequest) (resp *datastore.CreateAttestedNodeEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createAttestedNodeEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) FetchAttestedNodeEntry(ctx context.Context,
	req *datastore.FetchAttestedNodeEntryRequest) (resp *datastore.FetchAttestedNodeEntryResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchAttestedNodeEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) FetchStaleNodeEntries(ctx context.Context,
	req *datastore.FetchStaleNodeEntriesRequest) (resp *datastore.FetchStaleNodeEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchStaleNodeEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) UpdateAttestedNodeEntry(ctx context.Context,
	req *datastore.UpdateAttestedNodeEntryRequest) (resp *datastore.UpdateAttestedNodeEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateAttestedNodeEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) DeleteAttestedNodeEntry(ctx context.Context,
	req *datastore.DeleteAttestedNodeEntryRequest) (resp *datastore.DeleteAttestedNodeEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteAttestedNodeEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) CreateNodeResolverMapEntry(ctx context.Context,
	req *datastore.CreateNodeResolverMapEntryRequest) (resp *datastore.CreateNodeResolverMapEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createNodeResolverMapEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) FetchNodeResolverMapEntry(ctx context.Context,
	req *datastore.FetchNodeResolverMapEntryRequest) (resp *datastore.FetchNodeResolverMapEntryResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchNodeResolverMapEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) DeleteNodeResolverMapEntry(ctx context.Context,
	req *datastore.DeleteNodeResolverMapEntryRequest) (resp *datastore.DeleteNodeResolverMapEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteNodeResolverMapEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (sqlPlugin) RectifyNodeResolverMapEntries(ctx context.Context,
	req *datastore.RectifyNodeResolverMapEntriesRequest) (*datastore.RectifyNodeResolverMapEntriesResponse, error) {
	return &datastore.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

func (ds *sqlPlugin) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (resp *datastore.CreateRegistrationEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) FetchRegistrationEntry(ctx context.Context,
	req *datastore.FetchRegistrationEntryRequest) (resp *datastore.FetchRegistrationEntryResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) FetchRegistrationEntries(ctx context.Context,
	req *common.Empty) (resp *datastore.FetchRegistrationEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchRegistrationEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds sqlPlugin) UpdateRegistrationEntry(ctx context.Context,
	req *datastore.UpdateRegistrationEntryRequest) (resp *datastore.UpdateRegistrationEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) DeleteRegistrationEntry(ctx context.Context,
	req *datastore.DeleteRegistrationEntryRequest) (resp *datastore.DeleteRegistrationEntryResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) ListParentIDEntries(ctx context.Context,
	req *datastore.ListParentIDEntriesRequest) (resp *datastore.ListParentIDEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listParentIDEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) ListSelectorEntries(ctx context.Context,
	req *datastore.ListSelectorEntriesRequest) (resp *datastore.ListSelectorEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listSelectorEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) ListMatchingEntries(ctx context.Context,
	req *datastore.ListSelectorEntriesRequest) (resp *datastore.ListSelectorEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listMatchingEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) ListSpiffeEntries(ctx context.Context,
	req *datastore.ListSpiffeEntriesRequest) (resp *datastore.ListSpiffeEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listSpiffeEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// RegisterToken takes a Token message and stores it
func (ds *sqlPlugin) RegisterToken(ctx context.Context, req *datastore.JoinToken) (resp *common.Empty, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = registerToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (ds *sqlPlugin) FetchToken(ctx context.Context, req *datastore.JoinToken) (resp *datastore.JoinToken, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) DeleteToken(ctx context.Context, req *datastore.JoinToken) (resp *common.Empty, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *sqlPlugin) PruneTokens(ctx context.Context, req *datastore.JoinToken) (resp *common.Empty, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneTokens(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *sqlPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &configuration{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	if config.DatabaseType == "" {
		return nil, errors.New("database_type must be set")
	}

	if config.ConnectionString == "" {
		return nil, errors.New("connection_string must be set")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.db == nil ||
		config.ConnectionString != ds.db.connectionString ||
		config.DatabaseType != ds.db.databaseType {

		db, err := openDB(config.DatabaseType, config.ConnectionString)
		if err != nil {
			return nil, err
		}

		if ds.db != nil {
			ds.db.Close()
		}

		ds.db = &sqlDB{
			DB:               db,
			databaseType:     config.DatabaseType,
			connectionString: config.ConnectionString,
		}
	}

	ds.db.LogMode(config.LogSQL)

	return &spi.ConfigureResponse{}, nil
}

func (sqlPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (ds *sqlPlugin) withWriteTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, false)
}

func (ds *sqlPlugin) withReadTx(ctx context.Context, op func(tx *gorm.DB) error) error {
	return ds.withTx(ctx, op, true)
}

func (ds *sqlPlugin) withTx(ctx context.Context, op func(tx *gorm.DB) error, readOnly bool) error {
	ds.mu.Lock()
	db := ds.db
	ds.mu.Unlock()

	if db.databaseType == "sqlite3" && !readOnly {
		// sqlite3 can only have one writer at a time. since we're in WAL mode,
		// there can be concurrent reads and writes, so no lock is necessary
		// over the read operations.
		db.opMu.Lock()
		defer db.opMu.Unlock()
	}

	// TODO: as soon as GORM supports it, attach the context
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if err := op(tx); err != nil {
		tx.Rollback()
		return err
	}

	if readOnly {
		// rolling back makes sure that functions that are invoked with
		// withReadTx, and then do writes, will not pass unit tests, since the
		// writes won't be committed.
		return sqlError.Wrap(tx.Rollback().Error)
	}
	return sqlError.Wrap(tx.Commit().Error)
}

func openDB(databaseType, connectionString string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	switch databaseType {
	case "sqlite3":
		db, err = sqlite{}.connect(connectionString)
	case "postgres":
		db, err = postgres{}.connect(connectionString)
	default:
		return nil, sqlError.New("unsupported database_type: %v", databaseType)
	}
	if err != nil {
		return nil, err
	}

	if err := migrateDB(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func createBundle(tx *gorm.DB, req *datastore.Bundle) (*datastore.Bundle, error) {
	model, err := bundleToModel(req)
	if err != nil {
		return nil, err
	}

	if err := tx.Create(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return req, nil
}

func updateBundle(tx *gorm.DB, req *datastore.Bundle) (*datastore.Bundle, error) {
	newModel, err := bundleToModel(req)
	if err != nil {
		return nil, err
	}

	// Fetch the model to get its ID
	model := &Bundle{}
	if err := tx.Find(model, "trust_domain = ?", newModel.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Delete existing CA certs - the provided list takes precedence
	if err := tx.Where("bundle_id = ?", model.ID).Delete(CACert{}).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Set the new values
	model.CACerts = newModel.CACerts
	if err := tx.Save(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return req, nil
}

func appendBundle(tx *gorm.DB, req *datastore.Bundle) (*datastore.Bundle, error) {
	newModel, err := bundleToModel(req)
	if err != nil {
		return nil, err
	}

	// First, fetch the existing model
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.RecordNotFound() {
		return createBundle(tx, req)
	} else if result.Error != nil {
		return nil, sqlError.Wrap(result.Error)
	}

	// Get the existing certificates so we can include them in the response
	var caCerts []CACert
	if err := tx.Model(model).Related(&caCerts).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}
	model.CACerts = caCerts

	for _, newCA := range newModel.CACerts {
		if !model.Contains(newCA) {
			model.Append(newCA)
		}
	}

	if err := tx.Save(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func deleteBundle(tx *gorm.DB, req *datastore.Bundle) (*datastore.Bundle, error) {
	// We don't care if cert data was sent - remove it now to prevent
	// further processing.
	req.CaCerts = []byte{}

	model, err := bundleToModel(req)
	if err != nil {
		return nil, err
	}

	if err := tx.Find(model, "trust_domain = ?", model.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Fetch related CA certs for response before we delete them
	var caCerts []CACert
	if err := tx.Model(model).Related(&caCerts).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}
	model.CACerts = caCerts

	if err := tx.Where("bundle_id = ?", model.ID).Delete(CACert{}).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func fetchBundle(tx *gorm.DB, req *datastore.Bundle) (*datastore.Bundle, error) {
	model, err := bundleToModel(req)
	if err != nil {
		return nil, err
	}

	if err := tx.Find(model, "trust_domain = ?", model.TrustDomain).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Model(model).Related(&model.CACerts).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return modelToBundle(model)
}

// ListBundles can be used to fetch all existing bundles.
func listBundles(tx *gorm.DB, req *common.Empty) (*datastore.Bundles, error) {
	var bundles []Bundle
	if err := tx.Find(&bundles).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	var caCerts []CACert
	if err := tx.Find(&caCerts).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Index CA Certs by Bundle ID so we can reconstruct them more easily
	caMap := make(map[uint][]CACert)
	for _, cert := range caCerts {
		bundleID := cert.BundleID

		if _, ok := caMap[bundleID]; ok {
			caMap[bundleID] = append(caMap[bundleID], cert)
		} else {
			caMap[bundleID] = []CACert{cert}
		}
	}

	resp := &datastore.Bundles{}
	for _, model := range bundles {
		certs, ok := caMap[model.ID]
		if ok {
			model.CACerts = certs
		} else {
			model.CACerts = []CACert{}
		}

		bundle, err := modelToBundle(&model)
		if err != nil {
			return nil, err
		}

		resp.Bundles = append(resp.Bundles, bundle)
	}

	return resp, nil
}

func createAttestedNodeEntry(tx *gorm.DB, req *datastore.CreateAttestedNodeEntryRequest) (*datastore.CreateAttestedNodeEntryResponse, error) {
	entry := req.AttestedNodeEntry
	if entry == nil {
		return nil, sqlError.New("invalid request: missing attested node")
	}

	expiresAt, err := time.Parse(datastore.TimeFormat, entry.CertExpirationDate)
	if err != nil {
		return nil, sqlError.New("invalid request: missing expiration")
	}

	model := AttestedNodeEntry{
		SpiffeID:     entry.BaseSpiffeId,
		DataType:     entry.AttestationDataType,
		SerialNumber: entry.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:        model.SpiffeID,
			AttestationDataType: model.DataType,
			CertSerialNumber:    model.SerialNumber,
			CertExpirationDate:  expiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func fetchAttestedNodeEntry(tx *gorm.DB, req *datastore.FetchAttestedNodeEntryRequest) (*datastore.FetchAttestedNodeEntryResponse, error) {
	var model AttestedNodeEntry
	err := tx.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchAttestedNodeEntryResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}
	return &datastore.FetchAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:        model.SpiffeID,
			AttestationDataType: model.DataType,
			CertSerialNumber:    model.SerialNumber,
			CertExpirationDate:  model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func fetchStaleNodeEntries(tx *gorm.DB, req *datastore.FetchStaleNodeEntriesRequest) (*datastore.FetchStaleNodeEntriesResponse, error) {
	var models []AttestedNodeEntry
	if err := tx.Find(&models, "expires_at < ?", time.Now()).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.FetchStaleNodeEntriesResponse{
		AttestedNodeEntryList: make([]*datastore.AttestedNodeEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList, &datastore.AttestedNodeEntry{
			BaseSpiffeId:        model.SpiffeID,
			AttestationDataType: model.DataType,
			CertSerialNumber:    model.SerialNumber,
			CertExpirationDate:  model.ExpiresAt.Format(datastore.TimeFormat),
		})
	}
	return resp, nil
}

func updateAttestedNodeEntry(tx *gorm.DB, req *datastore.UpdateAttestedNodeEntryRequest) (*datastore.UpdateAttestedNodeEntryResponse, error) {
	expiresAt, err := time.Parse(datastore.TimeFormat, req.CertExpirationDate)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	var model AttestedNodeEntry
	if err := tx.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	updates := AttestedNodeEntry{
		SerialNumber: req.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := tx.Model(&model).Updates(updates).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:        model.SpiffeID,
			AttestationDataType: model.DataType,
			CertSerialNumber:    model.SerialNumber,
			CertExpirationDate:  model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func deleteAttestedNodeEntry(tx *gorm.DB, req *datastore.DeleteAttestedNodeEntryRequest) (*datastore.DeleteAttestedNodeEntryResponse, error) {
	var model AttestedNodeEntry
	if err := tx.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.DeleteAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:        model.SpiffeID,
			AttestationDataType: model.DataType,
			CertSerialNumber:    model.SerialNumber,
			CertExpirationDate:  model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func createNodeResolverMapEntry(tx *gorm.DB, req *datastore.CreateNodeResolverMapEntryRequest) (*datastore.CreateNodeResolverMapEntryResponse, error) {
	entry := req.NodeResolverMapEntry
	if entry == nil {
		return nil, sqlError.New("invalid request: no map entry")
	}

	selector := entry.Selector
	if selector == nil {
		return nil, sqlError.New("invalid request: no selector")
	}

	model := NodeResolverMapEntry{
		SpiffeID: entry.BaseSpiffeId,
		Type:     selector.Type,
		Value:    selector.Value,
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.CreateNodeResolverMapEntryResponse{
		NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeID,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		},
	}, nil
}

func fetchNodeResolverMapEntry(tx *gorm.DB, req *datastore.FetchNodeResolverMapEntryRequest) (*datastore.FetchNodeResolverMapEntryResponse, error) {
	var models []NodeResolverMapEntry
	if err := tx.Find(&models, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.FetchNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*datastore.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeID,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}
	return resp, nil
}

func deleteNodeResolverMapEntry(tx *gorm.DB, req *datastore.DeleteNodeResolverMapEntryRequest) (*datastore.DeleteNodeResolverMapEntryResponse, error) {
	entry := req.NodeResolverMapEntry
	if entry == nil {
		return nil, sqlError.New("invalid request: no map entry")
	}

	// if no selector is given, delete all entries with the given spiffe id
	scope := tx.Where("spiffe_id = ?", entry.BaseSpiffeId)

	if selector := entry.Selector; selector != nil {
		scope = scope.Where("type  = ?", selector.Type)
		scope = scope.Where("value = ?", selector.Value)
	}

	var models []NodeResolverMapEntry

	if err := scope.Find(&models).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := scope.Delete(&NodeResolverMapEntry{}).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	resp := &datastore.DeleteNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*datastore.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeID,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}

	return resp, nil
}

func createRegistrationEntry(tx *gorm.DB,
	req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	// TODO: Validations should be done in the ProtoBuf level [https://github.com/spiffe/spire/issues/44]
	if req.RegisteredEntry == nil {
		return nil, sqlError.New("invalid request: missing registered entry")
	}

	if err := validateRegistrationEntry(req.RegisteredEntry); err != nil {
		return nil, err
	}

	entryID, err := newRegistrationEntryID()
	if err != nil {
		return nil, err
	}

	newRegisteredEntry := RegisteredEntry{
		EntryID:  entryID,
		SpiffeID: req.RegisteredEntry.SpiffeId,
		ParentID: req.RegisteredEntry.ParentId,
		TTL:      req.RegisteredEntry.Ttl,
		// TODO: Add support to Federated Bundles [https://github.com/spiffe/spire/issues/42]
	}

	if err := tx.Create(&newRegisteredEntry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	for _, registeredSelector := range req.RegisteredEntry.Selectors {
		newSelector := Selector{
			RegisteredEntryID: newRegisteredEntry.ID,
			Type:              registeredSelector.Type,
			Value:             registeredSelector.Value}

		if err := tx.Create(&newSelector).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}
	}

	return &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: newRegisteredEntry.EntryID,
	}, nil
}

func fetchRegistrationEntry(tx *gorm.DB,
	req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	var fetchedRegisteredEntry RegisteredEntry
	err := tx.Find(&fetchedRegisteredEntry, "entry_id = ?", req.RegisteredEntryId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchRegistrationEntryResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	var fetchedSelectors []*Selector
	if err := tx.Model(&fetchedRegisteredEntry).Related(&fetchedSelectors).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	selectors := make([]*common.Selector, 0, len(fetchedSelectors))

	for _, selector := range fetchedSelectors {
		selectors = append(selectors, &common.Selector{
			Type:  selector.Type,
			Value: selector.Value})
	}

	return &datastore.FetchRegistrationEntryResponse{
		RegisteredEntry: &common.RegistrationEntry{
			EntryId:   fetchedRegisteredEntry.EntryID,
			Selectors: selectors,
			SpiffeId:  fetchedRegisteredEntry.SpiffeID,
			ParentId:  fetchedRegisteredEntry.ParentID,
			Ttl:       fetchedRegisteredEntry.TTL,
		},
	}, nil
}

func fetchRegistrationEntries(tx *gorm.DB,
	req *common.Empty) (*datastore.FetchRegistrationEntriesResponse, error) {

	var entries []RegisteredEntry
	if err := tx.Find(&entries).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	var sel []Selector
	if err := tx.Find(&sel).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Organize the selectors for easier access
	selectors := map[uint][]Selector{}
	for _, s := range sel {
		selectors[s.RegisteredEntryID] = append(selectors[s.RegisteredEntryID], s)
	}

	// Populate registration entries with their related selectors
	for _, entry := range entries {
		if s, ok := selectors[entry.ID]; ok {
			entry.Selectors = s
		}
	}

	resEntries, err := modelsToEntries(tx, entries)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.FetchRegistrationEntriesResponse{
		RegisteredEntries: &common.RegistrationEntries{
			Entries: resEntries,
		},
	}, nil
}

func updateRegistrationEntry(tx *gorm.DB,
	req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {

	if req.RegisteredEntry == nil {
		return nil, sqlError.New("no registration entry provided")
	}

	if err := validateRegistrationEntry(req.RegisteredEntry); err != nil {
		return nil, err
	}

	// Get the existing entry
	// TODO: Refactor message type to take EntryID directly from the entry - see #449
	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", req.RegisteredEntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	// Delete existing selectors - we will write new ones
	if err := tx.Exec("DELETE FROM selectors WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	selectors := []Selector{}
	for _, s := range req.RegisteredEntry.Selectors {
		selector := Selector{
			Type:  s.Type,
			Value: s.Value,
		}

		selectors = append(selectors, selector)
	}

	entry.SpiffeID = req.RegisteredEntry.SpiffeId
	entry.ParentID = req.RegisteredEntry.ParentId
	entry.TTL = req.RegisteredEntry.Ttl
	entry.Selectors = selectors
	if err := tx.Save(&entry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	req.RegisteredEntry.EntryId = entry.EntryID
	return &datastore.UpdateRegistrationEntryResponse{
		RegisteredEntry: req.RegisteredEntry,
	}, nil
}

func deleteRegistrationEntry(tx *gorm.DB,
	req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

	entry := RegisteredEntry{}
	if err := tx.Find(&entry, "entry_id = ?", req.RegisteredEntryId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&entry).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	respEntry, err := modelToEntry(tx, entry)
	if err != nil {
		return nil, err
	}

	return &datastore.DeleteRegistrationEntryResponse{
		RegisteredEntry: respEntry,
	}, nil
}

func listParentIDEntries(tx *gorm.DB,
	req *datastore.ListParentIDEntriesRequest) (*datastore.ListParentIDEntriesResponse, error) {

	var fetchedRegisteredEntries []RegisteredEntry
	err := tx.Find(&fetchedRegisteredEntries, "parent_id = ?", req.ParentId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.ListParentIDEntriesResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	regEntryList, err := modelsToEntries(tx, fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return &datastore.ListParentIDEntriesResponse{RegisteredEntryList: regEntryList}, nil
}

func listSelectorEntries(tx *gorm.DB,
	req *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	entries, err := listEntriesWithExactSelectorMatch(tx, req.Selectors)
	if err != nil {
		return nil, err
	}

	util.SortRegistrationEntries(entries)
	return &datastore.ListSelectorEntriesResponse{RegisteredEntryList: entries}, nil
}

func listMatchingEntries(tx *gorm.DB,
	req *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	resp := &datastore.ListSelectorEntriesResponse{}
	for combination := range selector.NewSetFromRaw(req.Selectors).Power() {
		entries, err := listEntriesWithExactSelectorMatch(tx, combination.Raw())
		if err != nil {
			return nil, err
		}
		resp.RegisteredEntryList = append(resp.RegisteredEntryList, entries...)
	}

	util.SortRegistrationEntries(resp.RegisteredEntryList)
	return resp, nil
}

func listSpiffeEntries(tx *gorm.DB,
	req *datastore.ListSpiffeEntriesRequest) (*datastore.ListSpiffeEntriesResponse, error) {

	var entries []RegisteredEntry
	if err := tx.Find(&entries, "spiffe_id = ?", req.SpiffeId).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	respEntries, err := modelsToEntries(tx, entries)
	if err != nil {
		return nil, err
	}

	return &datastore.ListSpiffeEntriesResponse{
		RegisteredEntryList: respEntries,
	}, nil
}

func registerToken(tx *gorm.DB, req *datastore.JoinToken) (*common.Empty, error) {
	if req.Token == "" || req.Expiry == 0 {
		return nil, errors.New("token and expiry are required")
	}

	t := JoinToken{
		Token:  req.Token,
		Expiry: req.Expiry,
	}

	if err := tx.Create(&t).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &common.Empty{}, nil
}

func fetchToken(tx *gorm.DB, req *datastore.JoinToken) (*datastore.JoinToken, error) {
	var t JoinToken
	err := tx.Find(&t, "token = ?", req.Token).Error
	if err == gorm.ErrRecordNotFound {
		return &datastore.JoinToken{}, nil
	} else if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.JoinToken{
		Token:  t.Token,
		Expiry: t.Expiry,
	}, nil
}

func deleteToken(tx *gorm.DB, req *datastore.JoinToken) (*common.Empty, error) {
	var t JoinToken
	if err := tx.Find(&t, "token = ?", req.Token).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	if err := tx.Delete(&t).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &common.Empty{}, nil
}

func pruneTokens(tx *gorm.DB, req *datastore.JoinToken) (*common.Empty, error) {
	if err := tx.Where("expiry <= ?", req.Expiry).Delete(&JoinToken{}).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &common.Empty{}, nil
}

// modelToBundle converts the given bundle model to a Protobuf bundle message. It will also
// include any embedded CACert models.
func modelToBundle(model *Bundle) (*datastore.Bundle, error) {
	id, err := idutil.ParseSpiffeID(model.TrustDomain, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	caCerts := []byte{}
	for _, c := range model.CACerts {
		caCerts = append(caCerts, c.Cert...)
	}

	pb := &datastore.Bundle{
		TrustDomain: id.String(),
		CaCerts:     caCerts,
	}

	return pb, nil
}

func validateRegistrationEntry(entry *common.RegistrationEntry) error {
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

// listEntriesWithExactSelectorMatch finds registered entries containing exactly the specified selectors.
func listEntriesWithExactSelectorMatch(tx *gorm.DB, selectors []*common.Selector) ([]*common.RegistrationEntry, error) {
	if len(selectors) < 1 {
		return nil, nil
	}

	// Count references to each entry ID
	refCount := make(map[uint]int)
	for _, s := range selectors {
		var results []Selector
		if err := tx.Find(&results, "type = ? AND value = ?", s.Type, s.Value).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		for _, r := range results {
			if count, ok := refCount[r.RegisteredEntryID]; ok {
				refCount[r.RegisteredEntryID] = count + 1
			} else {
				refCount[r.RegisteredEntryID] = 1
			}
		}
	}

	// Weed out entries that don't have every selector
	var entryIDs []uint
	for id, count := range refCount {
		if count == len(selectors) {
			entryIDs = append(entryIDs, id)
		}
	}

	// Fetch the distilled entries.
	var resp []RegisteredEntry
	for _, id := range entryIDs {
		var result RegisteredEntry
		if err := tx.Find(&result, "id = ?", id).Error; err != nil {
			return nil, sqlError.Wrap(err)
		}

		resp = append(resp, result)
	}

	// Weed out entries that have more selectors than requested, since only
	// EXACT matches should be returned.
	convertedEntries, err := modelsToUnsortedEntries(tx, resp)
	if err != nil {
		return nil, err
	}
	var entries []*common.RegistrationEntry
	for _, entry := range convertedEntries {
		if len(entry.Selectors) == len(selectors) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// bundleToModel converts the given Protobuf bundle message to a database model. It
// performs validation, and fully parses certificates to form CACert embedded models.
func bundleToModel(pb *datastore.Bundle) (*Bundle, error) {
	id, err := idutil.ParseSpiffeID(pb.TrustDomain, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	certs, err := x509.ParseCertificates(pb.CaCerts)
	if err != nil {
		return nil, sqlError.New("could not parse CA certificates")
	}

	// Translate CACerts, if any
	caCerts := []CACert{}
	for _, c := range certs {
		cert := CACert{
			Cert:   c.Raw,
			Expiry: c.NotAfter,
		}

		caCerts = append(caCerts, cert)
	}

	bundle := &Bundle{
		TrustDomain: id.String(),
		CACerts:     caCerts,
	}

	return bundle, nil
}

func modelsToEntries(tx *gorm.DB, fetchedRegisteredEntries []RegisteredEntry) (responseEntries []*common.RegistrationEntry, err error) {
	entries, err := modelsToUnsortedEntries(tx, fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	util.SortRegistrationEntries(entries)
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
	var selectors []*common.Selector
	var fetchedSelectors []*Selector
	if err := tx.Model(&model).Related(&fetchedSelectors).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	for _, selector := range fetchedSelectors {
		selectors = append(selectors, &common.Selector{
			Type:  selector.Type,
			Value: selector.Value})
	}
	return &common.RegistrationEntry{
		EntryId:   model.EntryID,
		Selectors: selectors,
		SpiffeId:  model.SpiffeID,
		ParentId:  model.ParentID,
		Ttl:       model.TTL,
	}, nil
}

func newRegistrationEntryID() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", sqlError.New("unable to generate registration entry id: %v", err)
	}
	return id.String(), nil
}

// NewTemp create a new plugin with a temporal database, allowing new
// connections to receive a fresh copy. Primarily meant for testing.
func NewTemp() (datastore.Plugin, error) {
	p := newPlugin()

	// Call restart() to start the db - normally triggered by call to Configure
	err := p.restart()
	if err != nil {
		return nil, fmt.Errorf("start database: %v", err)
	}

	p.db.LogMode(true)
	return p, nil
}
