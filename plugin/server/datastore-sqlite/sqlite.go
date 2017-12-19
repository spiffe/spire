package main

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/satori/go.uuid"
	sel "github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
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

type sqlitePlugin struct {
	db    *gorm.DB
	mutex *sync.Mutex
}

func (ds *sqlitePlugin) CreateFederatedEntry(
	req *datastore.CreateFederatedEntryRequest) (*datastore.CreateFederatedEntryResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

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

func (ds *sqlitePlugin) FetchRegistrationEntries(
	request *common.Empty) (*datastore.FetchRegistrationEntriesResponse, error) {

	var entries []registeredEntry
	if err := ds.db.Find(&entries).Error; err != nil {
		return nil, err
	}

	var sel []selector
	if err := ds.db.Find(&sel).Error; err != nil {
		return nil, err
	}

	// Organize the selectors for easier access
	selectors := map[string][]*selector{}
	for _, s := range sel {
		selectors[s.RegisteredEntryId] = append(selectors[s.RegisteredEntryId], &s)
	}

	// Populate registration entries with their related selectors
	for _, entry := range entries {
		if s, ok := selectors[entry.RegisteredEntryId]; ok {
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

func (sqlitePlugin) UpdateRegistrationEntry(
	*datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	return &datastore.UpdateRegistrationEntryResponse{}, errors.New("Not Implemented")
}

func (ds *sqlitePlugin) DeleteRegistrationEntry(
	request *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

	entry := registeredEntry{
		RegisteredEntryId: request.RegisteredEntryId,
	}
	if err := ds.db.Find(&entry).Error; err != nil {
		return &datastore.DeleteRegistrationEntryResponse{}, err
	}

	if err := ds.db.Delete(&entry).Error; err != nil {
		return &datastore.DeleteRegistrationEntryResponse{}, err
	}

	respEntry, err := ds.convertEntries([]registeredEntry{entry})
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

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if len(request.Selectors) < 1 {
		return &datastore.ListSelectorEntriesResponse{}, nil
	}

	//order selectors
	sort.Slice(request.Selectors, util.SelectorsSortFunction(request.Selectors))
	//build compound selector
	compoundSelector := ""
	for _, selector := range request.Selectors {
		compoundSelector += selector.Type + selector.Value
	}

	var fetchedRegisteredEntries []registeredEntry
	query := getListSelectorQuery(1)
	ds.db.
		Raw(query, compoundSelector).
		Scan(&fetchedRegisteredEntries)

	regEntryList, err := ds.convertEntries(fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return &datastore.ListSelectorEntriesResponse{RegisteredEntryList: regEntryList}, nil
}

func (ds *sqlitePlugin) ListMatchingEntries(
	request *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if len(request.Selectors) < 1 {
		return &datastore.ListSelectorEntriesResponse{}, nil
	}

	set := sel.NewSet(request.Selectors)
	compoundSelectors := []interface{}{}
	//iterate the powerset so we can create the compound selector for each subset
	for subset := range set.Power() {
		selectorSubSet := subset.Raw()
		//order selectors for each subset before creating the compound selector
		sort.Slice(selectorSubSet, util.SelectorsSortFunction(selectorSubSet))
		//build compound selector for each subset
		var compoundSelector string
		for _, selector := range selectorSubSet {
			compoundSelector += selector.Type + selector.Value
		}
		compoundSelectors = append(compoundSelectors, compoundSelector)
	}

	var fetchedRegisteredEntries []registeredEntry
	query := getListSelectorQuery(len(compoundSelectors))
	ds.db.
		Raw(query, compoundSelectors...).
		Scan(&fetchedRegisteredEntries)

	regEntryList, err := ds.convertEntries(fetchedRegisteredEntries)
	if err != nil {
		return nil, err
	}
	return &datastore.ListSelectorEntriesResponse{RegisteredEntryList: regEntryList}, nil
}

func (ds *sqlitePlugin) ListSpiffeEntries(
	request *datastore.ListSpiffeEntriesRequest) (*datastore.ListSpiffeEntriesResponse, error) {

	var entries []registeredEntry
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

	t := joinToken{
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

	var t joinToken

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

	t := joinToken{
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

	var staleTokens []joinToken
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

func (sqlitePlugin) Configure(*spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (sqlitePlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
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

func newPlugin(dbType string) (datastore.DataStore, error) {
	db, err := gorm.Open("sqlite3", dbType)
	if err != nil {
		return nil, err
	}

	db.LogMode(true)

	if err := migrateDB(db); err != nil {
		return nil, err
	}

	return &sqlitePlugin{
		db:    db,
		mutex: &sync.Mutex{},
	}, nil

}

//New creates a new sqlite plugin with
//an in-memory database and shared cache
func New() (datastore.DataStore, error) {
	return newPlugin("file::memory:?cache=shared")
}

//NewTemp create a new plugin with a temporal database,
//different connections won't access the same database
func NewTemp() (datastore.DataStore, error) {
	return newPlugin("")
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

func getListSelectorQuery(conditionCount int) string {
	query := `
SELECT *, group_concat(selector, '') as compound 
FROM (
	SELECT (selectors.type || selectors.value) as selector, 
	* 
	FROM registered_entries JOIN selectors 
	ON selectors.registered_entry_id = registered_entries.registered_entry_id
	ORDER BY  selectors.type, selectors.value
)
GROUP BY registered_entry_id 
HAVING compound = ? `

	if conditionCount > 1 {
		for i := 1; i < conditionCount; i++ {
			query += "OR compound = ? "
		}
	}
	query += "ORDER BY spiffe_id"
	return query
}
