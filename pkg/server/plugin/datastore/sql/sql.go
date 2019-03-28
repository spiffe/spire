package sql

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/hcl"
	"github.com/jinzhu/gorm"

	// gorm sqlite dialect init registration
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/spiffe/spire/pkg/common/bundleutil"
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

const (
	MySQL      = "mysql"
	PostgreSQL = "postgres"
	SQLite     = "sqlite3"
)

type configuration struct {
	DatabaseType     string `hcl:"database_type" json:"database_type"`
	ConnectionString string `hcl:"connection_string" json:"connection_string"`
	RootCAPath       string `hcl:"root_ca_path" json:"root_ca_path"`
	ClientCertPath   string `hcl:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath    string `hcl:"client_key_path" json:"client_key_path"`

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
func (ds *sqlPlugin) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (resp *datastore.CreateBundleResponse, err error) {
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
func (ds *sqlPlugin) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (resp *datastore.UpdateBundleResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *sqlPlugin) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (resp *datastore.AppendBundleResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = appendBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *sqlPlugin) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (resp *datastore.DeleteBundleResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *sqlPlugin) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (resp *datastore.FetchBundleResponse, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *sqlPlugin) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (resp *datastore.ListBundlesResponse, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listBundles(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateAttestedNode stores the given attested node
func (ds *sqlPlugin) CreateAttestedNode(ctx context.Context,
	req *datastore.CreateAttestedNodeRequest) (resp *datastore.CreateAttestedNodeResponse, err error) {
	if req.Node == nil {
		return nil, sqlError.New("invalid request: missing attested node")
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchAttestedNode fetches an existing attested node by SPIFFE ID
func (ds *sqlPlugin) FetchAttestedNode(ctx context.Context,
	req *datastore.FetchAttestedNodeRequest) (resp *datastore.FetchAttestedNodeResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListAttestedNodes lists all attested nodes (pagination available)
func (ds *sqlPlugin) ListAttestedNodes(ctx context.Context,
	req *datastore.ListAttestedNodesRequest) (resp *datastore.ListAttestedNodesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodes(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateAttestedNode updates the given node's cert serial and expiration.
func (ds *sqlPlugin) UpdateAttestedNode(ctx context.Context,
	req *datastore.UpdateAttestedNodeRequest) (resp *datastore.UpdateAttestedNodeResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteAttestedNode deletes the given attested node
func (ds *sqlPlugin) DeleteAttestedNode(ctx context.Context,
	req *datastore.DeleteAttestedNodeRequest) (resp *datastore.DeleteAttestedNodeResponse, err error) {

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteAttestedNode(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// SetNodeSelectors sets node (agent) selectors by SPIFFE ID, deleting old selectors first
func (ds *sqlPlugin) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (resp *datastore.SetNodeSelectorsResponse, err error) {
	if req.Selectors == nil {
		return nil, errors.New("invalid request: missing selectors")
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = setNodeSelectors(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// GetNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *sqlPlugin) GetNodeSelectors(ctx context.Context,
	req *datastore.GetNodeSelectorsRequest) (resp *datastore.GetNodeSelectorsResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = getNodeSelectors(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateRegistrationEntry stores the given registration entry
func (ds *sqlPlugin) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (resp *datastore.CreateRegistrationEntryResponse, err error) {
	// TODO: Validations should be done in the ProtoBuf level [https://github.com/spiffe/spire/issues/44]
	if err := validateRegistrationEntry(req.Entry); err != nil {
		return nil, err
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
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

// ListRegistrationEntries lists all registrations (pagination available)
func (ds *sqlPlugin) ListRegistrationEntries(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest) (resp *datastore.ListRegistrationEntriesResponse, err error) {

	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listRegistrationEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateRegistrationEntry updates an existing registration entry
func (ds *sqlPlugin) UpdateRegistrationEntry(ctx context.Context,
	req *datastore.UpdateRegistrationEntryRequest) (resp *datastore.UpdateRegistrationEntryResponse, err error) {
	if err := validateRegistrationEntry(req.Entry); err != nil {
		return nil, err
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = updateRegistrationEntry(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteRegistrationEntry deletes the given registration
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

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
// before the date in the message
func (ds *sqlPlugin) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (resp *datastore.PruneRegistrationEntriesResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneRegistrationEntries(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateJoinToken takes a Token message and stores it
func (ds *sqlPlugin) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (resp *datastore.CreateJoinTokenResponse, err error) {
	if req.JoinToken == nil || req.JoinToken.Token == "" || req.JoinToken.Expiry == 0 {
		return nil, errors.New("token and expiry are required")
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = createJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// FetchJoinToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (ds *sqlPlugin) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (resp *datastore.FetchJoinTokenResponse, err error) {
	if err := ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteJoinToken deletes the given join token
func (ds *sqlPlugin) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (resp *datastore.DeleteJoinTokenResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = deleteJoinToken(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneJoinTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *sqlPlugin) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (resp *datastore.PruneJoinTokensResponse, err error) {
	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = pruneJoinTokens(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// Configure parses HCL config payload into config struct, and opens new DB based on the result
func (ds *sqlPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &configuration{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	if err := validateDBConfig(config); err != nil {
		return nil, err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.db == nil ||
		config.ConnectionString != ds.db.connectionString ||
		config.DatabaseType != ds.db.databaseType {

		db, err := openDB(config)
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

// GetPluginInfo returns the sql plugin
func (*sqlPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
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

	if db.databaseType == SQLite && !readOnly {
		// sqlite3 can only have one writer at a time. since we're in WAL mode,
		// there can be concurrent reads and writes, so no lock is necessary
		// over the read operations.
		db.opMu.Lock()
		defer db.opMu.Unlock()
	}

	// TODO: as soon as GORM supports it, attach the context
	// https://github.com/jinzhu/gorm/issues/1231
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

func openDB(cfg *configuration) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

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

	if err := migrateDB(db, cfg.DatabaseType); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
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
					registered_entries.id
				FROM
					registered_entries
				INNER JOIN
					federated_registration_entries
				ON
					federated_registration_entries.registered_entry_id = registered_entries.id
				WHERE
					federated_registration_entries.bundle_id = ?)`), model.ID).Error; err != nil {
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
	if p != nil && p.PageSize > 0 {
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

	if p != nil && p.PageSize > 0 && len(models) > 0 {
		lastEntry := models[len(models)-1]
		p.Token = fmt.Sprint(lastEntry.ID)
	}

	resp := &datastore.ListAttestedNodesResponse{
		Nodes:      make([]*datastore.AttestedNode, 0, len(models)),
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

func getNodeSelectors(tx *gorm.DB, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	var models []NodeSelector
	if err := tx.Where("spiffe_id = ?", req.SpiffeId).Find(&models).Error; err != nil {
		return nil, sqlError.Wrap(err)
	}

	var selectors []*common.Selector
	for _, selector := range models {
		selectors = append(selectors, &common.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		})
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

func fetchRegistrationEntry(tx *gorm.DB,
	req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	var fetchedRegisteredEntry RegisteredEntry
	err := tx.Find(&fetchedRegisteredEntry, "entry_id = ?", req.EntryId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchRegistrationEntryResponse{}, nil
	case err != nil:
		return nil, sqlError.Wrap(err)
	}

	entry, err := modelToEntry(tx, fetchedRegisteredEntry)
	if err != nil {
		return nil, err
	}

	return &datastore.FetchRegistrationEntryResponse{
		Entry: entry,
	}, nil
}

func listRegistrationEntries(tx *gorm.DB,
	req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	var p *datastore.Pagination
	var err error

	// list of selector sets to match against
	var selectorsList [][]*common.Selector
	if req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
		selectorSet := selector.NewSetFromRaw(req.BySelectors.Selectors)
		switch req.BySelectors.Match {
		case datastore.BySelectors_MATCH_SUBSET:
			for combination := range selectorSet.Power() {
				selectorsList = append(selectorsList, combination.Raw())
			}
		case datastore.BySelectors_MATCH_EXACT:
			selectorsList = append(selectorsList, selectorSet.Raw())
		default:
			return nil, fmt.Errorf("unhandled match behavior %q", req.BySelectors.Match)
		}
	}

	// filter registration entries
	entryTx := tx
	if req.ByParentId != nil {
		entryTx = entryTx.Where("parent_id = ?", req.ByParentId.Value)
	}
	if req.BySpiffeId != nil {
		entryTx = entryTx.Where("spiffe_id = ?", req.BySpiffeId.Value)
	}

	if len(selectorsList) == 0 {
		// no selectors to filter against.
		var entries []RegisteredEntry
		entries, p, err = findRegisteredEntries(entryTx, req.Pagination)
		if err != nil {
			return nil, sqlError.Wrap(err)
		}

		respEntries, err := modelsToEntries(tx, entries)
		if err != nil {
			return nil, sqlError.Wrap(err)
		}

		return &datastore.ListRegistrationEntriesResponse{
			Entries:    respEntries,
			Pagination: p,
		}, nil
	}

	modelsSet := make(map[uint]RegisteredEntry)
	for _, selectors := range selectorsList {
		refCount := make(map[uint]int)
		for _, s := range selectors {
			var results []Selector
			if err := tx.Find(&results, "type = ? AND value = ?", s.Type, s.Value).Error; err != nil {
				return nil, sqlError.Wrap(err)
			}

			for _, r := range results {
				refCount[r.RegisteredEntryID]++
			}
		}

		// exclude entry ids that don't have an exact number of selectors
		entryIDs := make([]uint, 0, len(refCount))
		for id, count := range refCount {
			if count == len(selectors) {
				entryIDs = append(entryIDs, id)
			}
		}
		if len(entryIDs) == 0 {
			continue
		}

		// fetch the entries in the id set, filtered by any parent/spiffe id filters
		// applied globally
		db := entryTx.Where(entryIDs)
		var models []RegisteredEntry
		models, p, err = findRegisteredEntries(db, req.Pagination)
		if err != nil {
			return nil, err
		}

		for _, model := range models {
			var count int
			if err := tx.Model(&Selector{}).Where("registered_entry_id = ?", model.ID).Count(&count).Error; err != nil {
				return nil, sqlError.Wrap(err)
			}
			if count == len(selectors) {
				modelsSet[model.ID] = model
			}
		}
	}

	models := make([]RegisteredEntry, 0, len(modelsSet))
	for _, model := range modelsSet {
		models = append(models, model)
	}

	entries, err := modelsToEntries(tx, models)
	if err != nil {
		return nil, sqlError.Wrap(err)
	}

	return &datastore.ListRegistrationEntriesResponse{
		Entries:    entries,
		Pagination: p,
	}, nil
}

// applyPagination  add order limit and token to current query
func applyPagination(p *datastore.Pagination, entryTx *gorm.DB) (*gorm.DB, error) {
	if p.Token == "" {
		p.Token = "0"
	}

	id, err := strconv.ParseUint(p.Token, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse token '%v'", p.Token)
	}
	return entryTx.Order("id asc").Limit(p.PageSize).Where("id > ?", id), nil
}

// update pagination token based in last result in returned list
func updatePaginationToken(p *datastore.Pagination, entries []RegisteredEntry) {
	if len(entries) == 0 {
		return
	}
	lastEntry := (entries)[len(entries)-1]
	p.Token = fmt.Sprint(lastEntry.ID)
}

// find registered entries using pagination in case it is configured
func findRegisteredEntries(entryTx *gorm.DB, p *datastore.Pagination) ([]RegisteredEntry, *datastore.Pagination, error) {
	var entries []RegisteredEntry
	var err error

	// if pagination is not nil and page size is greater than 0, add pagination
	if p != nil && p.PageSize > 0 {
		entryTx, err = applyPagination(p, entryTx)

		if err != nil {
			return nil, nil, err
		}
	}

	// find by results
	if err := entryTx.Find(&entries).Error; err != nil {
		return nil, nil, sqlError.Wrap(err)
	}

	if p != nil && p.PageSize > 0 {
		updatePaginationToken(p, entries)
	}

	return entries, p, nil
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
func modelToBundle(model *Bundle) (*datastore.Bundle, error) {
	bundle := new(datastore.Bundle)
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
func bundleToModel(pb *datastore.Bundle) (*Bundle, error) {
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
	if err := tx.Model(&model).Related(&fetchedDNSs).Error; err != nil {
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

func modelToAttestedNode(model AttestedNode) *datastore.AttestedNode {
	return &datastore.AttestedNode{
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

func validateDBConfig(cfg *configuration) error {
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
