package services

import (
	"github.com/spiffe/sri/pkg/common"
	ds "github.com/spiffe/sri/control_plane/plugins/data_store"
)

//Registration service interface.
type Registration interface {
	CreateEntry(entry *common.RegistrationEntry) (registeredID string, err error)
	FetchEntry(registeredID string) (entry *common.RegistrationEntry, err error)
}

//RegistrationImpl is an implementation of the Registration interface.
type RegistrationImpl struct {
	dataStore ds.DataStore
}

//NewRegistrationImpl creastes a new RegistrationImpl.
func NewRegistrationImpl(dataStore ds.DataStore) RegistrationImpl {
	return RegistrationImpl{dataStore: dataStore}
}

//CreateEntry with the DataStore plugin.
func (r RegistrationImpl) CreateEntry(entry *common.RegistrationEntry) (string, error) {
	dsEntry := &ds.RegisteredEntry{
		ParentId: entry.ParentId,
		SpiffeId: entry.SpiffeId,
		Ttl:      entry.Ttl,
		FederatedBundleSpiffeIdList: entry.FbSpiffeIds,
	}

	for _, s := range entry.Selectors {
		selector := &ds.Selector{
			Type:  s.Type,
			Value: s.Value,
		}
		dsEntry.SelectorList = append(dsEntry.SelectorList, selector)
	}

	response, err := r.dataStore.CreateRegistrationEntry(&ds.CreateRegistrationEntryRequest{
		RegisteredEntry: dsEntry,
	})

	if err != nil {
		return "", err
	}

	return response.RegisteredEntryId, nil
}

//FetchEntry gets a RegisteredEntry based on a registeredID.
func (r RegistrationImpl) FetchEntry(registeredID string) (*common.RegistrationEntry, error) {
	response, err := r.dataStore.FetchRegistrationEntry(&ds.FetchRegistrationEntryRequest{RegisteredEntryId: registeredID})

	if err != nil {
		return nil, err
	}

	protoEntry := &common.RegistrationEntry{
		ParentId: response.RegisteredEntry.ParentId,
		SpiffeId: response.RegisteredEntry.SpiffeId,
		Ttl:      response.RegisteredEntry.Ttl,
	}

	for _, s := range response.RegisteredEntry.SelectorList {
		selector := &common.Selector{
			Type:  s.Type,
			Value: s.Value,
		}
		protoEntry.Selectors = append(protoEntry.Selectors, selector)
	}

	return protoEntry, nil
}
