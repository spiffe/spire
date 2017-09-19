package main

import (
	"errors"

	"github.com/hashicorp/go-plugin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/satori/go.uuid"

	"time"

	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/plugin"

	"github.com/spiffe/spire/pkg/server/datastore"
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
	req *datastore.CreateFederatedEntryRequest) (*datastore.CreateFederatedEntryResponse, error) {

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

	return &datastore.CreateFederatedEntryResponse{}, nil
}

func (ds *sqlitePlugin) ListFederatedEntry(
	*datastore.ListFederatedEntryRequest) (*datastore.ListFederatedEntryResponse, error) {
	var entries []federatedBundle
	var response datastore.ListFederatedEntryResponse

	if err := ds.db.Find(&entries).Error; err != nil {
		return &response, err
	}

	for _, model := range entries {
		response.FederatedBundleSpiffeIdList = append(response.FederatedBundleSpiffeIdList, model.SpiffeId)
	}

	return &response, nil
}

func (ds *sqlitePlugin) UpdateFederatedEntry(
	req *datastore.UpdateFederatedEntryRequest) (*datastore.UpdateFederatedEntryResponse, error) {
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

	return &datastore.UpdateFederatedEntryResponse{
		FederatedBundle: &datastore.FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteFederatedEntry(
	req *datastore.DeleteFederatedEntryRequest) (*datastore.DeleteFederatedEntryResponse, error) {
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

	return &datastore.DeleteFederatedEntryResponse{
		FederatedBundle: &datastore.FederatedBundle{
			FederatedBundleSpiffeId: model.SpiffeId,
			FederatedTrustBundle:    model.Bundle,
			Ttl:                     model.Ttl,
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) CreateAttestedNodeEntry(
	req *datastore.CreateAttestedNodeEntryRequest) (*datastore.CreateAttestedNodeEntryResponse, error) {
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

	return &datastore.CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: expiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchAttestedNodeEntry(
	req *datastore.FetchAttestedNodeEntryRequest) (*datastore.FetchAttestedNodeEntryResponse, error) {
	var model attestedNodeEntry
	err := ds.db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchAttestedNodeEntryResponse{}, nil
	case err != nil:
		return nil, err
	}
	return &datastore.FetchAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchStaleNodeEntries(
	*datastore.FetchStaleNodeEntriesRequest) (*datastore.FetchStaleNodeEntriesResponse, error) {

	var models []attestedNodeEntry
	if err := ds.db.Find(&models, "expires_at < ?", time.Now()).Error; err != nil {
		return nil, err
	}

	resp := &datastore.FetchStaleNodeEntriesResponse{
		AttestedNodeEntryList: make([]*datastore.AttestedNodeEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList, &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) UpdateAttestedNodeEntry(
	req *datastore.UpdateAttestedNodeEntryRequest) (*datastore.UpdateAttestedNodeEntryResponse, error) {

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

	return &datastore.UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteAttestedNodeEntry(
	req *datastore.DeleteAttestedNodeEntryRequest) (*datastore.DeleteAttestedNodeEntryResponse, error) {
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

	return &datastore.DeleteAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeId,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) CreateNodeResolverMapEntry(
	req *datastore.CreateNodeResolverMapEntryRequest) (*datastore.CreateNodeResolverMapEntryResponse, error) {

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

	return &datastore.CreateNodeResolverMapEntryResponse{
		NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		},
	}, nil
}

func (ds *sqlitePlugin) FetchNodeResolverMapEntry(
	req *datastore.FetchNodeResolverMapEntryRequest) (*datastore.FetchNodeResolverMapEntryResponse, error) {
	var models []nodeResolverMapEntry

	if err := ds.db.Find(&models, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, err
	}

	resp := &datastore.FetchNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*datastore.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) DeleteNodeResolverMapEntry(
	req *datastore.DeleteNodeResolverMapEntryRequest) (*datastore.DeleteNodeResolverMapEntryResponse, error) {

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

	resp := &datastore.DeleteNodeResolverMapEntryResponse{
		NodeResolverMapEntryList: make([]*datastore.NodeResolverMapEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.NodeResolverMapEntryList = append(resp.NodeResolverMapEntryList, &datastore.NodeResolverMapEntry{
			BaseSpiffeId: model.SpiffeId,
			Selector: &common.Selector{
				Type:  model.Type,
				Value: model.Value,
			},
		})
	}

	return resp, tx.Commit().Error
}

func (sqlitePlugin) RectifyNodeResolverMapEntries(
	*datastore.RectifyNodeResolverMapEntriesRequest) (*datastore.RectifyNodeResolverMapEntriesResponse, error) {
	return &datastore.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

func (ds *sqlitePlugin) CreateRegistrationEntry(
	request *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	// TODO: Validations should be done in the ProtoBuf level [https://github.com/spiffe/spire/issues/44]
	if request.RegisteredEntry == nil {
		return nil, errors.New("Invalid request: missing registered entry")
	} else if request.RegisteredEntry.Selectors == nil || len(request.RegisteredEntry.Selectors) == 0 {
		return nil, errors.New("Invalid request: missing selector list")
	} else if len(request.RegisteredEntry.SpiffeId) == 0 {
		return nil, errors.New("Invalid request: missing SPIFFE ID")
	} else if request.RegisteredEntry.Ttl < 0 {
		return nil, errors.New("Invalid request: TTL < 0")
	}

	newRegisteredEntry := registeredEntry{
		RegisteredEntryId: uuid.NewV4().String(),
		SpiffeId:          request.RegisteredEntry.SpiffeId,
		ParentId:          request.RegisteredEntry.ParentId,
		Ttl:               request.RegisteredEntry.Ttl,
		// TODO: Add support to Federated Bundles [https://github.com/spiffe/spire/issues/42]
	}

	tx := ds.db.Begin()
	if err := tx.Create(&newRegisteredEntry).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	for _, registeredSelector := range request.RegisteredEntry.Selectors {
		newSelector := selector{
			RegisteredEntryId: newRegisteredEntry.RegisteredEntryId,
			Type:              registeredSelector.Type,
			Value:             registeredSelector.Value}

		if err := tx.Create(&newSelector).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	return &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: newRegisteredEntry.RegisteredEntryId,
	}, tx.Commit().Error
}

func (ds *sqlitePlugin) FetchRegistrationEntry(
	request *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	var fetchedRegisteredEntry registeredEntry
	err := ds.db.Find(&fetchedRegisteredEntry, "registered_entry_id = ?", request.RegisteredEntryId).Error

	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchRegistrationEntryResponse{}, nil
	case err != nil:
		return nil, err
	}

	var fetchedSelectors []*selector
	ds.db.Model(&fetchedRegisteredEntry).Related(&fetchedSelectors)

	selectors := make([]*common.Selector, 0, len(fetchedSelectors))

	for _, selector := range fetchedSelectors {
		selectors = append(selectors, &common.Selector{
			Type:  selector.Type,
			Value: selector.Value})
	}

	return &datastore.FetchRegistrationEntryResponse{
		RegisteredEntry: &common.RegistrationEntry{
			Selectors: selectors,
			SpiffeId:  fetchedRegisteredEntry.SpiffeId,
			ParentId:  fetchedRegisteredEntry.ParentId,
			Ttl:       fetchedRegisteredEntry.Ttl,
		},
	}, nil
}

func (sqlitePlugin) UpdateRegistrationEntry(
	*datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	return &datastore.UpdateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) DeleteRegistrationEntry(
	*datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {
	return &datastore.DeleteRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (ds *sqlitePlugin) ListParentIDEntries(
	request *datastore.ListParentIDEntriesRequest) (response *datastore.ListParentIDEntriesResponse, err error) {
	var fetchedRegisteredEntries []registeredEntry
	err = ds.db.Find(&fetchedRegisteredEntries, "parent_id = ?", request.ParentId).Error

	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.ListParentIDEntriesResponse{}, nil
	case err != nil:
		return nil, err
	}

	regEntryList, err := ds.convertEntries(fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return &datastore.ListParentIDEntriesResponse{RegisteredEntryList: regEntryList}, nil
}

func (ds *sqlitePlugin) ListSelectorEntries(
	request *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	var fetchedRegisteredEntries []registeredEntry
	err := ds.db.Joins("JOIN selectors ON selectors.registered_entry_id = registered_entries.registered_entry_id").
		Where("selectors.type = ? and selectors.value = ?", request.Selector.Type, request.Selector.Value).
		Find(&fetchedRegisteredEntries).
		Error

	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.ListSelectorEntriesResponse{}, nil
	case err != nil:
		return nil, err
	}

	regEntryList, err := ds.convertEntries(fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return &datastore.ListSelectorEntriesResponse{RegisteredEntryList: regEntryList}, nil
}

func (sqlitePlugin) ListSpiffeEntries(
	*datastore.ListSpiffeEntriesRequest) (*datastore.ListSpiffeEntriesResponse, error) {
	return &datastore.ListSpiffeEntriesResponse{}, errors.New("Not Implemented")
}

func (sqlitePlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (sqlitePlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (ds *sqlitePlugin) convertEntries(fetchedRegisteredEntries []registeredEntry) (responseEntries []*common.RegistrationEntry, err error) {
	for _, regEntry := range fetchedRegisteredEntries {
		var selectors []*common.Selector
		var fetchedSelectors []*selector
		if err = ds.db.Model(&regEntry).Related(&fetchedSelectors).Error; err != nil {
			return nil, err
		}

		for _, selector := range fetchedSelectors {
			selectors = append(selectors, &common.Selector{
				Type:  selector.Type,
				Value: selector.Value})
		}
		responseEntries = append(responseEntries, &common.RegistrationEntry{
			Selectors: selectors,
			SpiffeId:  regEntry.SpiffeId,
			ParentId:  regEntry.ParentId,
			Ttl:       regEntry.Ttl,
		})
	}
	return responseEntries, nil
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
