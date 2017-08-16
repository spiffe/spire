package main

import (
	"errors"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
	proto "github.com/spiffe/sri/control_plane/plugins/data_store/proto"
)

var (
	pluginInfo = common.GetPluginInfoResponse{
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
	req *proto.CreateFederatedEntryRequest) (*proto.CreateFederatedEntryResponse, error) {

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

	return &proto.CreateFederatedEntryResponse{}, nil
}

func (ds *sqlitePlugin) ListFederatedEntry(
	*proto.ListFederatedEntryRequest) (*proto.ListFederatedEntryResponse, error) {
	var entries []federatedBundle
	var response proto.ListFederatedEntryResponse

	if err := ds.db.Find(&entries).Error; err != nil {
		return &response, err
	}

	for _, model := range entries {
		response.FederatedBundleSpiffeIdList = append(response.FederatedBundleSpiffeIdList, model.SpiffeId)
	}

	return &response, nil
}

func (ds *sqlitePlugin) UpdateFederatedEntry(
	req *proto.UpdateFederatedEntryRequest) (*proto.UpdateFederatedEntryResponse, error) {
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

	return &proto.UpdateFederatedEntryResponse{
		FederatedBundle: &proto.FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteFederatedEntry(
	req *proto.DeleteFederatedEntryRequest) (*proto.DeleteFederatedEntryResponse, error) {
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

	return &proto.DeleteFederatedEntryResponse{
		FederatedBundle: &proto.FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

//

func (ds *sqlitePlugin) CreateAttestedNodeEntry(
	req *proto.CreateAttestedNodeEntryRequest) (*proto.CreateAttestedNodeEntryResponse, error) {
	entry := req.AttestedNodeEntry
	if entry == nil {
		return nil, errors.New("invalid request: missing attested node")
	}

	expiresAt, err := time.Parse(datastore.TimeFormat, entry.CertExpirationDate)
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

	return &proto.CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: &proto.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: expiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchAttestedNodeEntry(
	req *proto.FetchAttestedNodeEntryRequest) (*proto.FetchAttestedNodeEntryResponse, error) {
	var model attestedNodeEntry
	err := ds.db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &proto.FetchAttestedNodeEntryResponse{}, nil
	case err != nil:
		return nil, err
	}
	return &proto.FetchAttestedNodeEntryResponse{
		AttestedNodeEntry: &proto.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchStaleNodeEntries(
	*proto.FetchStaleNodeEntriesRequest) (*proto.FetchStaleNodeEntriesResponse, error) {

	var models []attestedNodeEntry
	if err := ds.db.Find(&models, "expires_at < ?", time.Now()).Error; err != nil {
		return nil, err
	}

	resp := &proto.FetchStaleNodeEntriesResponse{
		AttestedNodeEntryList: make([]*proto.AttestedNodeEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList, &proto.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) UpdateAttestedNodeEntry(
	req *proto.UpdateAttestedNodeEntryRequest) (*proto.UpdateAttestedNodeEntryResponse, error) {

	var model attestedNodeEntry

	expiresAt, err := time.Parse(datastore.TimeFormat, req.CertExpirationDate)
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

	return &proto.UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: &proto.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteAttestedNodeEntry(
	req *proto.DeleteAttestedNodeEntryRequest) (*proto.DeleteAttestedNodeEntryResponse, error) {
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

	return &proto.DeleteAttestedNodeEntryResponse{
		AttestedNodeEntry: &proto.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

//

func (ds *sqlitePlugin) CreateNodeResolverMapEntry(
	req *proto.CreateNodeResolverMapEntryRequest) (*proto.CreateNodeResolverMapEntryResponse, error) {

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

	return &proto.CreateNodeResolverMapEntryResponse{
		NodeResolverMapEntry: &proto.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &proto.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		},
	}, nil
}

func (ds *sqlitePlugin) FetchNodeResolverMapEntry(
	req *proto.FetchNodeResolverMapEntryRequest) (*proto.FetchNodeResolverMapEntryResponse, error) {
	var models []nodeResolverMapEntry

	if err := ds.db.Find(&models, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, err
	}

	resp := &proto.FetchNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*proto.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &proto.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &proto.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) DeleteNodeResolverMapEntry(
	req *proto.DeleteNodeResolverMapEntryRequest) (*proto.DeleteNodeResolverMapEntryResponse, error) {

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

	resp := &proto.DeleteNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*proto.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &proto.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &proto.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}

	return resp, tx.Commit().Error
}

func (sqlitePlugin) RectifyNodeResolverMapEntries(
	*proto.RectifyNodeResolverMapEntriesRequest) (*proto.RectifyNodeResolverMapEntriesResponse, error) {
	return &proto.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) CreateRegistrationEntry(
	*proto.CreateRegistrationEntryRequest) (*proto.CreateRegistrationEntryResponse, error) {
	return &proto.CreateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) FetchRegistrationEntry(
	*proto.FetchRegistrationEntryRequest) (*proto.FetchRegistrationEntryResponse, error) {
	return &proto.FetchRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) UpdateRegistrationEntry(
	*proto.UpdateRegistrationEntryRequest) (*proto.UpdateRegistrationEntryResponse, error) {
	return &proto.UpdateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) DeleteRegistrationEntry(
	*proto.DeleteRegistrationEntryRequest) (*proto.DeleteRegistrationEntryResponse, error) {
	return &proto.DeleteRegistrationEntryResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) ListParentIDEntries(
	*proto.ListParentIDEntriesRequest) (*proto.ListParentIDEntriesResponse, error) {
	return &proto.ListParentIDEntriesResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) ListSelectorEntries(
	*proto.ListSelectorEntriesRequest) (*proto.ListSelectorEntriesResponse, error) {
	return &proto.ListSelectorEntriesResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) ListSpiffeEntries(
	*proto.ListSpiffeEntriesRequest) (*proto.ListSpiffeEntriesResponse, error) {
	return &proto.ListSpiffeEntriesResponse{}, errors.New("Not Implemented")
}

//

func (sqlitePlugin) Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error) {
	return &common.ConfigureResponse{}, nil
}

func (sqlitePlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func New() (datastore.DataStore, error) {
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
		HandshakeConfig: datastore.Handshake,
		Plugins: map[string]plugin.Plugin{
			"datastore": datastore.DataStorePlugin{DataStoreImpl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
