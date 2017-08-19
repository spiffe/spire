package main

import (
	"errors"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"github.com/spiffe/sri/common/plugin"
    // XXX . is not ideal here
	. "github.com/spiffe/sri/control_plane/plugins/data_store"
)

var (
	pluginInfo = sriplugin.GetPluginInfoResponse{
		Description: "",
		DateCreated: "",
		Version:     "",
		Author:      "",
		Company:     "",
	}
)

type sqlitePlugin struct {
	db *gorm.DB
}

func (ds *sqlitePlugin) CreateFederatedEntry(
	req *CreateFederatedEntryRequest) (*CreateFederatedEntryResponse, error) {

	bundle := req.FederatedBundle
	if bundle == nil {
		return nil, errors.New("invalid request: no bundle given")
	}

	model := federatedBundle{
		SpiffeId: bundle.FederatedBundleSpiffeId,
		Bundle:   bundle.FederatedTrustBundle,
		Ttl:      bundle.Ttl,
	}

	if err := ds.db.Create(&model).Error; err != nil {
		return nil, err
	}

	return &CreateFederatedEntryResponse{}, nil
}

func (ds *sqlitePlugin) ListFederatedEntry(
	*ListFederatedEntryRequest) (*ListFederatedEntryResponse, error) {
	var entries []federatedBundle
	var response ListFederatedEntryResponse

	if err := ds.db.Find(&entries).Error; err != nil {
		return &response, err
	}

	for _, model := range entries {
		response.FederatedBundleSpiffeIdList = append(response.FederatedBundleSpiffeIdList, model.SpiffeId)
	}

	return &response, nil
}

func (ds *sqlitePlugin) UpdateFederatedEntry(
	req *UpdateFederatedEntryRequest) (*UpdateFederatedEntryResponse, error) {
	bundle := req.FederatedBundle

	if bundle == nil {
		return nil, errors.New("invalid request: no bundle given")
	}

	db := ds.db.Begin()

	var model federatedBundle

	if err := db.Find(&model, "spiffe_id = ?", bundle.FederatedBundleSpiffeId).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	updates := federatedBundle{
		Bundle: bundle.FederatedTrustBundle,
		Ttl:    bundle.Ttl,
	}

	if err := db.Model(&model).Updates(updates).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	return &UpdateFederatedEntryResponse{
		FederatedBundle: &FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteFederatedEntry(
	req *DeleteFederatedEntryRequest) (*DeleteFederatedEntryResponse, error) {
	db := ds.db.Begin()

	var model federatedBundle

	if err := db.Find(&model, "spiffe_id = ?", req.FederatedBundleSpiffeId).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	if err := db.Delete(&model).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	return &DeleteFederatedEntryResponse{
		FederatedBundle: &FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

//

func (ds *sqlitePlugin) CreateAttestedNodeEntry(
	req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	entry := req.AttestedNodeEntry
	if entry == nil {
		return nil, errors.New("invalid request: missing attested node")
	}

	expiresAt, err := time.Parse(TimeFormat, entry.CertExpirationDate)
	if err != nil {
		return nil, errors.New("invalid request: missing expiration")
	}

	model := attestedNodeEntry{
		SpiffeId:     entry.BaseSpiffeId,
		DataType:     entry.AttestedDataType,
		SerialNumber: entry.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := ds.db.Create(&model).Error; err != nil {
		return nil, err
	}

	return &CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: &AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: expiresAt.Format(TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchAttestedNodeEntry(
	req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	var model attestedNodeEntry
	err := ds.db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &FetchAttestedNodeEntryResponse{}, nil
	case err != nil:
		return nil, err
	}
	return &FetchAttestedNodeEntryResponse{
		AttestedNodeEntry: &AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchStaleNodeEntries(
	*FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {

	var models []attestedNodeEntry
	if err := ds.db.Find(&models, "expires_at < ?", time.Now()).Error; err != nil {
		return nil, err
	}

	resp := &FetchStaleNodeEntriesResponse{
		AttestedNodeEntryList: make([]*AttestedNodeEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList, &AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(TimeFormat),
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) UpdateAttestedNodeEntry(
	req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {

	var model attestedNodeEntry

	expiresAt, err := time.Parse(TimeFormat, req.CertExpirationDate)
	if err != nil {
		return nil, err
	}

	db := ds.db.Begin()

	if err := db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	updates := attestedNodeEntry{
		SerialNumber: req.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := db.Model(&model).Updates(updates).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	return &UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: &AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteAttestedNodeEntry(
	req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	db := ds.db.Begin()

	var model attestedNodeEntry

	if err := db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	if err := db.Delete(&model).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	return &DeleteAttestedNodeEntryResponse{
		AttestedNodeEntry: &AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(TimeFormat),
		},
	}, db.Commit().Error
}

//

func (ds *sqlitePlugin) CreateNodeResolverMapEntry(
	req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {

	entry := req.NodeResolverMapEntry
	if entry == nil {
		return nil, errors.New("Invalid Request: no map entry")
	}

	selector := entry.Selector
	if selector == nil {
		return nil, errors.New("Invalid Request: no selector")
	}

	model := nodeResolverMapEntry{
		SpiffeId: entry.BaseSpiffeId,
		Type:     selector.Type,
		Value:    selector.Value,
	}

	if err := ds.db.Create(&model).Error; err != nil {
		return nil, err
	}

	return &CreateNodeResolverMapEntryResponse{
		NodeResolverMapEntry: &NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		},
	}, nil
}

func (ds *sqlitePlugin) FetchNodeResolverMapEntry(
	req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	var models []nodeResolverMapEntry

	if err := ds.db.Find(&models, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, err
	}

	resp := &FetchNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) DeleteNodeResolverMapEntry(
	req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {

	entry := req.NodeResolverMapEntry
	if entry == nil {
		return nil, errors.New("Invalid Request: no map entry")
	}

	tx := ds.db.Begin()

	// if no selector is given, delete all entries with the given spiffe id

	scope := tx.Where("spiffe_id = ?", entry.BaseSpiffeId)

	if selector := entry.Selector; selector != nil {
		scope = scope.Where("type  = ?", selector.Type)
		scope = scope.Where("value = ?", selector.Value)
	}

	var models []nodeResolverMapEntry

	if err := scope.Find(&models).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := scope.Delete(&nodeResolverMapEntry{}).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	resp := &DeleteNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}

	return resp, tx.Commit().Error
}

func (sqlitePlugin) RectifyNodeResolverMapEntries(
	*RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return &RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) CreateRegistrationEntry(
	*CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return &CreateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) FetchRegistrationEntry(
	*FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return &FetchRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) UpdateRegistrationEntry(
	*UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return &UpdateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) DeleteRegistrationEntry(
	*DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return &DeleteRegistrationEntryResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) ListParentIDEntries(
	*ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return &ListParentIDEntriesResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) ListSelectorEntries(
	*ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return &ListSelectorEntriesResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) ListSpiffeEntries(
	*ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return &ListSpiffeEntriesResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (sqlitePlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func New() (DataStore, error) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}

	db.LogMode(true)

	if err := migrateDB(db); err != nil {
		return nil, err
	}

	return &sqlitePlugin{
		db: db,
	}, nil
}

func main() {

	impl, err := New()
	if err != nil {
		panic(err.Error())
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]plugin.Plugin{
			"datastore": DataStorePlugin{DataStoreImpl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
