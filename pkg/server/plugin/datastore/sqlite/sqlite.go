package sqlite

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/datastore"
)

var (
	pluginInfo = spi.GetPluginInfoResponse{
		Description: "",
		DateCreated: "",
		Version:     "",
		Author:      "",
		Company:     "",
	}
)

type configuration struct {
	FileName string `hcl:"file_name" json:"file_name"`
}

type sqlitePlugin struct {
	db *gorm.DB

	// Path to use for sqlite db
	fileName string

	mutex *sync.Mutex
}

// CreateBundle stores the given bundle
func (ds *sqlitePlugin) CreateBundle(req *datastore.Bundle) (*datastore.Bundle, error) {
	model, err := ds.bundleToModel(req)
	if err != nil {
		return nil, err
	}

	result := ds.db.Create(model)
	if result.Error != nil {
		return nil, result.Error
	}

	return req, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *sqlitePlugin) UpdateBundle(req *datastore.Bundle) (*datastore.Bundle, error) {
	newModel, err := ds.bundleToModel(req)
	if err != nil {
		return nil, err
	}

	tx := ds.db.Begin()

	// Fetch the model to get its ID
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	// Delete existing CA certs - the provided list takes precedence
	result = tx.Where("bundle_id = ?", model.ID).Delete(CACert{})
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	// Set the new values
	model.CACerts = newModel.CACerts
	result = tx.Save(model)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	return req, tx.Commit().Error
}

// AppendBundle adds the specified CA certificates to an existing bundle. If no bundle exists for the
// specified trust domain, create one. Returns the entirety.
func (ds *sqlitePlugin) AppendBundle(req *datastore.Bundle) (*datastore.Bundle, error) {
	newModel, err := ds.bundleToModel(req)
	if err != nil {
		return nil, err
	}

	tx := ds.db.Begin()

	// First, fetch the existing model
	model := &Bundle{}
	result := tx.Find(model, "trust_domain = ?", newModel.TrustDomain)

	if result.RecordNotFound() {
		tx.Rollback()
		return ds.CreateBundle(req)
	} else if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	// Get the existing certificates so we can include them in the response
	var caCerts []CACert
	result = tx.Model(model).Related(&caCerts)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}
	model.CACerts = caCerts

	for _, newCA := range newModel.CACerts {
		if !model.Contains(newCA) {
			model.Append(newCA)
		}
	}

	result = tx.Save(model)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	resp, err := ds.modelToBundle(model)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	return resp, tx.Commit().Error
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *sqlitePlugin) DeleteBundle(req *datastore.Bundle) (*datastore.Bundle, error) {
	// We don't care if cert data was sent - remove it now to prevent
	// further processing.
	req.CaCerts = []byte{}

	model, err := ds.bundleToModel(req)
	if err != nil {
		return nil, err
	}

	tx := ds.db.Begin()

	result := tx.Find(model, "trust_domain = ?", model.TrustDomain)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	// Fetch related CA certs for response before we delete them
	var caCerts []CACert
	result = tx.Model(model).Related(&caCerts)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}
	model.CACerts = caCerts

	result = tx.Where("bundle_id = ?", model.ID).Delete(CACert{})
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	result = tx.Delete(model)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	resp, err := ds.modelToBundle(model)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	return resp, tx.Commit().Error
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *sqlitePlugin) FetchBundle(req *datastore.Bundle) (*datastore.Bundle, error) {
	model, err := ds.bundleToModel(req)
	if err != nil {
		return nil, err
	}

	result := ds.db.Find(model, "trust_domain = ?", model.TrustDomain)
	if result.Error != nil {
		return nil, result.Error
	}

	var caCerts []CACert
	result = ds.db.Model(model).Related(&caCerts)
	if result.Error != nil {
		return nil, result.Error
	}
	model.CACerts = caCerts

	return ds.modelToBundle(model)
}

// ListBundles can be used to fetch all existing bundles.
func (ds *sqlitePlugin) ListBundles(*common.Empty) (*datastore.Bundles, error) {
	// Get a consistent view
	tx := ds.db.Begin()
	defer tx.Rollback()

	var bundles []Bundle
	result := tx.Find(&bundles)
	if result.Error != nil {
		return nil, result.Error
	}

	var caCerts []CACert
	result = tx.Find(&caCerts)
	if result.Error != nil {
		return nil, result.Error
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

		bundle, err := ds.modelToBundle(&model)
		if err != nil {
			return nil, err
		}

		resp.Bundles = append(resp.Bundles, bundle)
	}

	return resp, nil
}

func (ds *sqlitePlugin) CreateAttestedNodeEntry(
	req *datastore.CreateAttestedNodeEntryRequest) (*datastore.CreateAttestedNodeEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	entry := req.AttestedNodeEntry
	if entry == nil {
		return nil, errors.New("invalid request: missing attested node")
	}

	expiresAt, err := time.Parse(datastore.TimeFormat, entry.CertExpirationDate)
	if err != nil {
		return nil, errors.New("invalid request: missing expiration")
	}

	model := AttestedNodeEntry{
		SpiffeID:     entry.BaseSpiffeId,
		DataType:     entry.AttestedDataType,
		SerialNumber: entry.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := ds.db.Create(&model).Error; err != nil {
		return nil, err
	}

	return &datastore.CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeID,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: expiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchAttestedNodeEntry(
	req *datastore.FetchAttestedNodeEntryRequest) (*datastore.FetchAttestedNodeEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var model AttestedNodeEntry
	err := ds.db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchAttestedNodeEntryResponse{}, nil
	case err != nil:
		return nil, err
	}
	return &datastore.FetchAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeID,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, nil
}

func (ds *sqlitePlugin) FetchStaleNodeEntries(
	*datastore.FetchStaleNodeEntriesRequest) (*datastore.FetchStaleNodeEntriesResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var models []AttestedNodeEntry
	if err := ds.db.Find(&models, "expires_at < ?", time.Now()).Error; err != nil {
		return nil, err
	}

	resp := &datastore.FetchStaleNodeEntriesResponse{
		AttestedNodeEntryList: make([]*datastore.AttestedNodeEntry, 0, len(models)),
	}

	for _, model := range models {
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList, &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeID,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		})
	}
	return resp, nil
}

func (ds *sqlitePlugin) UpdateAttestedNodeEntry(
	req *datastore.UpdateAttestedNodeEntryRequest) (*datastore.UpdateAttestedNodeEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var model AttestedNodeEntry

	expiresAt, err := time.Parse(datastore.TimeFormat, req.CertExpirationDate)
	if err != nil {
		return nil, err
	}

	db := ds.db.Begin()

	if err := db.Find(&model, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	updates := AttestedNodeEntry{
		SerialNumber: req.CertSerialNumber,
		ExpiresAt:    expiresAt,
	}

	if err := db.Model(&model).Updates(updates).Error; err != nil {
		db.Rollback()
		return nil, err
	}

	return &datastore.UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			BaseSpiffeId:       model.SpiffeID,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) DeleteAttestedNodeEntry(
	req *datastore.DeleteAttestedNodeEntryRequest) (*datastore.DeleteAttestedNodeEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	db := ds.db.Begin()

	var model AttestedNodeEntry

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
			BaseSpiffeId:       model.SpiffeID,
			AttestedDataType:   model.DataType,
			CertSerialNumber:   model.SerialNumber,
			CertExpirationDate: model.ExpiresAt.Format(datastore.TimeFormat),
		},
	}, db.Commit().Error
}

func (ds *sqlitePlugin) CreateNodeResolverMapEntry(
	req *datastore.CreateNodeResolverMapEntryRequest) (*datastore.CreateNodeResolverMapEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	entry := req.NodeResolverMapEntry
	if entry == nil {
		return nil, errors.New("Invalid Request: no map entry")
	}

	selector := entry.Selector
	if selector == nil {
		return nil, errors.New("Invalid Request: no selector")
	}

	model := NodeResolverMapEntry{
		SpiffeID: entry.BaseSpiffeId,
		Type:     selector.Type,
		Value:    selector.Value,
	}

	if err := ds.db.Create(&model).Error; err != nil {
		return nil, err
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

func (ds *sqlitePlugin) FetchNodeResolverMapEntry(
	req *datastore.FetchNodeResolverMapEntryRequest) (*datastore.FetchNodeResolverMapEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var models []NodeResolverMapEntry

	if err := ds.db.Find(&models, "spiffe_id = ?", req.BaseSpiffeId).Error; err != nil {
		return nil, err
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

func (ds *sqlitePlugin) DeleteNodeResolverMapEntry(
	req *datastore.DeleteNodeResolverMapEntryRequest) (*datastore.DeleteNodeResolverMapEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	var models []NodeResolverMapEntry

	if err := scope.Find(&models).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := scope.Delete(&NodeResolverMapEntry{}).Error; err != nil {
		tx.Rollback()
		return nil, err
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

	return resp, tx.Commit().Error
}

func (sqlitePlugin) RectifyNodeResolverMapEntries(
	*datastore.RectifyNodeResolverMapEntriesRequest) (*datastore.RectifyNodeResolverMapEntriesResponse, error) {
	return &datastore.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

func (ds *sqlitePlugin) CreateRegistrationEntry(
	request *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// TODO: Validations should be done in the ProtoBuf level [https://github.com/spiffe/spire/issues/44]
	if request.RegisteredEntry == nil {
		return nil, errors.New("Invalid request: missing registered entry")
	}

	err := ds.validateRegistrationEntry(request.RegisteredEntry)
	if err != nil {
		return nil, fmt.Errorf("Invalid registration entry: %v", err)
	}

	entryID, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("could not generate entry id: %v", err)
	}

	newRegisteredEntry := RegisteredEntry{
		EntryID:  entryID.String(),
		SpiffeID: request.RegisteredEntry.SpiffeId,
		ParentID: request.RegisteredEntry.ParentId,
		TTL:      request.RegisteredEntry.Ttl,
		// TODO: Add support to Federated Bundles [https://github.com/spiffe/spire/issues/42]
	}

	tx := ds.db.Begin()
	if err := tx.Create(&newRegisteredEntry).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	for _, registeredSelector := range request.RegisteredEntry.Selectors {
		newSelector := Selector{
			RegisteredEntryID: newRegisteredEntry.ID,
			Type:              registeredSelector.Type,
			Value:             registeredSelector.Value}

		if err := tx.Create(&newSelector).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	return &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: newRegisteredEntry.EntryID,
	}, tx.Commit().Error
}

func (ds *sqlitePlugin) FetchRegistrationEntry(
	request *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var fetchedRegisteredEntry RegisteredEntry
	err := ds.db.Find(&fetchedRegisteredEntry, "entry_id = ?", request.RegisteredEntryId).Error

	switch {
	case err == gorm.ErrRecordNotFound:
		return &datastore.FetchRegistrationEntryResponse{}, nil
	case err != nil:
		return nil, err
	}

	var fetchedSelectors []*Selector
	ds.db.Model(&fetchedRegisteredEntry).Related(&fetchedSelectors)

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

func (ds *sqlitePlugin) FetchRegistrationEntries(
	request *common.Empty) (*datastore.FetchRegistrationEntriesResponse, error) {

	var entries []RegisteredEntry
	if err := ds.db.Find(&entries).Error; err != nil {
		return nil, err
	}

	var sel []Selector
	if err := ds.db.Find(&sel).Error; err != nil {
		return nil, err
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

	resEntries, err := ds.convertEntries(entries)
	if err != nil {
		return nil, err
	}

	res := &datastore.FetchRegistrationEntriesResponse{
		RegisteredEntries: &common.RegistrationEntries{
			Entries: resEntries,
		},
	}

	return res, nil
}

func (ds sqlitePlugin) UpdateRegistrationEntry(
	request *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {

	if request.RegisteredEntry == nil {
		return nil, errors.New("No registration entry provided")
	}

	err := ds.validateRegistrationEntry(request.RegisteredEntry)
	if err != nil {
		return nil, fmt.Errorf("Invalid registration entry: %v", err)
	}

	tx := ds.db.Begin()

	// Get the existing entry
	// TODO: Refactor message type to take EntryID directly from the entry - see #449
	entry := RegisteredEntry{}
	if err = tx.Find(&entry, "entry_id = ?", request.RegisteredEntryId).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Delete existing selectors - we will write new ones
	if err = tx.Exec("DELETE FROM selectors WHERE registered_entry_id = ?", entry.ID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	selectors := []Selector{}
	for _, s := range request.RegisteredEntry.Selectors {
		selector := Selector{
			Type:  s.Type,
			Value: s.Value,
		}

		selectors = append(selectors, selector)
	}

	entry.SpiffeID = request.RegisteredEntry.SpiffeId
	entry.ParentID = request.RegisteredEntry.ParentId
	entry.TTL = request.RegisteredEntry.Ttl
	entry.Selectors = selectors
	if err = tx.Save(&entry).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err = tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	request.RegisteredEntry.EntryId = entry.EntryID
	return &datastore.UpdateRegistrationEntryResponse{RegisteredEntry: request.RegisteredEntry}, nil
}

func (ds *sqlitePlugin) DeleteRegistrationEntry(
	request *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

	entry := RegisteredEntry{}
	if err := ds.db.Find(&entry, "entry_id = ?", request.RegisteredEntryId).Error; err != nil {
		return &datastore.DeleteRegistrationEntryResponse{}, err
	}

	if err := ds.db.Delete(&entry).Error; err != nil {
		return &datastore.DeleteRegistrationEntryResponse{}, err
	}

	respEntry, err := ds.convertEntries([]RegisteredEntry{entry})
	if err != nil {
		return &datastore.DeleteRegistrationEntryResponse{}, err
	}

	resp := &datastore.DeleteRegistrationEntryResponse{
		RegisteredEntry: respEntry[0],
	}
	return resp, nil
}

func (ds *sqlitePlugin) ListParentIDEntries(
	request *datastore.ListParentIDEntriesRequest) (response *datastore.ListParentIDEntriesResponse, err error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var fetchedRegisteredEntries []RegisteredEntry
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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if len(request.Selectors) < 1 {
		return &datastore.ListSelectorEntriesResponse{}, nil
	}

	matches, err := ds.listMatchingEntries(request.Selectors)
	if err != nil {
		return &datastore.ListSelectorEntriesResponse{}, err
	}

	// Only keep entries which match the specified list exactly
	var entries []*common.RegistrationEntry
	for _, m := range matches {
		if len(m.Selectors) == len(request.Selectors) {
			entries = append(entries, m)
		}
	}

	resp := &datastore.ListSelectorEntriesResponse{RegisteredEntryList: entries}
	return resp, err
}

func (ds *sqlitePlugin) ListMatchingEntries(
	request *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if len(request.Selectors) < 1 {
		return &datastore.ListSelectorEntriesResponse{}, nil
	}

	entries, err := ds.listMatchingEntries(request.Selectors)
	if err != nil {
		return &datastore.ListSelectorEntriesResponse{}, err
	}

	resp := &datastore.ListSelectorEntriesResponse{RegisteredEntryList: entries}
	return resp, nil
}

func (ds *sqlitePlugin) ListSpiffeEntries(
	request *datastore.ListSpiffeEntriesRequest) (*datastore.ListSpiffeEntriesResponse, error) {

	var entries []RegisteredEntry
	err := ds.db.Find(&entries, "spiffe_id = ?", request.SpiffeId).Error
	if err != nil {
		return &datastore.ListSpiffeEntriesResponse{}, err
	}

	respEntries, err := ds.convertEntries(entries)
	if err != nil {
		return &datastore.ListSpiffeEntriesResponse{}, err
	}

	resp := &datastore.ListSpiffeEntriesResponse{
		RegisteredEntryList: respEntries,
	}
	return resp, nil
}

// RegisterToken takes a Token message and stores it
func (ds *sqlitePlugin) RegisterToken(req *datastore.JoinToken) (*common.Empty, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	resp := new(common.Empty)
	if req.Token == "" || req.Expiry == 0 {
		return resp, errors.New("token and expiry are required")
	}

	t := JoinToken{
		Token:  req.Token,
		Expiry: req.Expiry,
	}

	return resp, ds.db.Create(&t).Error
}

// FetchToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (ds *sqlitePlugin) FetchToken(req *datastore.JoinToken) (*datastore.JoinToken, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var t JoinToken

	err := ds.db.Find(&t, "token = ?", req.Token).Error
	if err == gorm.ErrRecordNotFound {
		return &datastore.JoinToken{}, nil
	}

	resp := &datastore.JoinToken{
		Token:  t.Token,
		Expiry: t.Expiry,
	}
	return resp, err
}

func (ds *sqlitePlugin) DeleteToken(req *datastore.JoinToken) (*common.Empty, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	resp := new(common.Empty)

	// Protect the data - if gorm gets a delete w/ an empty primary
	// key, it deletes _all_ the records...
	if req.Token == "" {
		return &common.Empty{}, errors.New("no token specified")
	}

	t := JoinToken{
		Token:  req.Token,
		Expiry: req.Expiry,
	}
	return resp, ds.db.Delete(&t).Error
}

// PruneTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *sqlitePlugin) PruneTokens(req *datastore.JoinToken) (*common.Empty, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	var staleTokens []JoinToken
	resp := new(common.Empty)

	err := ds.db.Where("expiry <= ?", req.Expiry).Find(&staleTokens).Error
	if err != nil {
		return resp, err
	}

	for _, t := range staleTokens {
		err := ds.db.Delete(&t).Error
		if err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func (ds *sqlitePlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &configuration{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	if config.FileName == "" {
		return resp, errors.New("filename must be set")
	}

	if config.FileName != ds.fileName {
		ds.fileName = config.FileName
		return resp, ds.restart()
	}

	return resp, nil
}

func (sqlitePlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

// listMatchingEntries finds registered entries containing all specified selectors. Note
// that entries containing _more_ than the specified selectors may be returned, since
// that is also considered a "match"
func (ds *sqlitePlugin) listMatchingEntries(selectors []*common.Selector) ([]*common.RegistrationEntry, error) {
	// Count references to each entry ID
	refCount := make(map[uint]int)
	for _, s := range selectors {
		var results []Selector
		err := ds.db.Find(&results, "type = ? AND value = ?", s.Type, s.Value).Error
		if err != nil {
			return []*common.RegistrationEntry{}, err
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

	// Finally, fetch and return the distilled entries
	var resp []RegisteredEntry
	for _, id := range entryIDs {
		var result RegisteredEntry
		err := ds.db.Find(&result, "id = ?", id).Error
		if err != nil {
			return []*common.RegistrationEntry{}, err
		}

		resp = append(resp, result)
	}

	return ds.convertEntries(resp)
}

// bundleToModel converts the given Protobuf bundle message to a database model. It
// performs validation, and fully parses certificates to form CACert embedded models.
func (ds *sqlitePlugin) bundleToModel(pb *datastore.Bundle) (*Bundle, error) {
	id, err := ds.validateTrustDomain(pb.TrustDomain)
	if err != nil {
		return nil, err
	}

	certs, err := x509.ParseCertificates(pb.CaCerts)
	if err != nil {
		return nil, errors.New("could not parse CA certificates")
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

// modelToBundle converts the given bundle model to a Protobuf bundle message. It will also
// include any embedded CACert models.
func (ds *sqlitePlugin) modelToBundle(model *Bundle) (*datastore.Bundle, error) {
	id, err := ds.validateTrustDomain(model.TrustDomain)
	if err != nil {
		return nil, err
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

func (ds *sqlitePlugin) validateRegistrationEntry(entry *common.RegistrationEntry) error {
	if entry.Selectors == nil || len(entry.Selectors) == 0 {
		return errors.New("missing selector list")
	}

	if len(entry.SpiffeId) == 0 {
		return errors.New("missing SPIFFE ID")
	}

	if entry.Ttl < 0 {
		return errors.New("TTL is not set")
	}

	return nil
}

// validateTrustDomain converts the given string to a URL, and ensures that it is a correctly
// formatted SPIFFE trust domain. String is taken as the argument here since neither Protobuf nor
// GORM natively support the url.URL type.
//
// A valid trust domain has the SPIFFE scheme, a non-zero host component, and no path
func (ds *sqlitePlugin) validateTrustDomain(in string) (*url.URL, error) {
	if in == "" {
		return nil, errors.New("trust domain is required")
	}

	id, err := url.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("could not parse trust domain %v: %v", in, err)
	}

	if id.Scheme != "spiffe" || id.Host == "" || (id.Path != "" && id.Path != "/") {
		return nil, fmt.Errorf("%v is not a valid SPIFFE trust domain", id.String())
	}

	return id, nil
}

func (ds *sqlitePlugin) convertEntries(fetchedRegisteredEntries []RegisteredEntry) (responseEntries []*common.RegistrationEntry, err error) {
	for _, regEntry := range fetchedRegisteredEntries {
		var selectors []*common.Selector
		var fetchedSelectors []*Selector
		if err = ds.db.Model(&regEntry).Related(&fetchedSelectors).Error; err != nil {
			return nil, err
		}

		for _, selector := range fetchedSelectors {
			selectors = append(selectors, &common.Selector{
				Type:  selector.Type,
				Value: selector.Value})
		}
		responseEntries = append(responseEntries, &common.RegistrationEntry{
			EntryId:   regEntry.EntryID,
			Selectors: selectors,
			SpiffeId:  regEntry.SpiffeID,
			ParentId:  regEntry.ParentID,
			Ttl:       regEntry.TTL,
		})
	}
	return ds.sortEntries(responseEntries), nil
}

// registrationEntries provides a sortable type to help ensure stable
// return ordering
type registrationEntries []*common.RegistrationEntry

func (re registrationEntries) Len() int      { return len(re) }
func (re registrationEntries) Swap(i, j int) { re[i], re[j] = re[j], re[i] }
func (re registrationEntries) Less(i, j int) bool {
	if re[i].SpiffeId < re[j].SpiffeId || re[i].ParentId < re[j].ParentId ||
		re[i].Ttl < re[j].Ttl || len(re[i].Selectors) < len(re[i].Selectors) {
		return true
	}

	return false
}

func (ds *sqlitePlugin) sortEntries(entries []*common.RegistrationEntry) []*common.RegistrationEntry {
	e := registrationEntries(entries)
	sort.Sort(e)
	return []*common.RegistrationEntry(e)
}

// restart will close and re-open the sqlite database.
func (ds *sqlitePlugin) restart() error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// Build sqlite connect string
	path := ds.fileName
	if path == ":memory:" {
		path = path + "?cache=shared"
	}
	path = "file:" + path

	log.Printf("opening sqlite database with path %s", path)
	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		return err
	}

	if ds.db != nil {
		ds.db.Close()
	}

	db.Exec("PRAGMA foreign_keys = ON")
	migrateDB(db)
	ds.db = db
	return nil
}

func newPlugin() *sqlitePlugin {
	p := &sqlitePlugin{
		mutex: new(sync.Mutex),
	}

	return p
}

// New creates a new sqlite plugin struct. Configure must be called
// in order to start the db.
func New() datastore.DataStore {
	return newPlugin()
}

// NewTemp create a new plugin with a temporal database, allowing new
// connections to receive a fresh copy. Primarily meant for testing.
func NewTemp() (datastore.DataStore, error) {
	p := newPlugin()

	// Call restart() to start the db - normally triggered by call to Configure
	err := p.restart()
	if err != nil {
		return nil, fmt.Errorf("start database: %v", err)
	}

	p.db.LogMode(true)
	return p, nil
}
