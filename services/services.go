package services

import (
	proto "github.com/spiffe/sri/control_plane/api/registration/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
	ds "github.com/spiffe/sri/control_plane/plugins/data_store/proto"
)

//Registration service interface.
type Registration interface {
	CreateEntry(entry *proto.RegisteredEntry) (registeredID string, err error)
	FetchEntry(registeredID string) (entry *proto.RegisteredEntry, err error)
}

//RegistrationImpl is an implementation of the Registration interface.
type RegistrationImpl struct {
	dataStore datastore.DataStore
}

//NewRegistrationImpl creastes a new RegistrationImpl.
func NewRegistrationImpl(dataStore datastore.DataStore) RegistrationImpl {
	return RegistrationImpl{}
}

//CreateEntry with the DataStore plugin.
func (r RegistrationImpl) CreateEntry(entry *proto.RegisteredEntry) (string, error) {
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
func (r RegistrationImpl) FetchEntry(registeredID string) (entry *proto.RegisteredEntry, err error) {
	response, err := r.dataStore.FetchRegistrationEntry(&ds.FetchRegistrationEntryRequest{RegisteredEntryId: registeredID})

	if err != nil {
		return nil, err
	}

	protoEntry := &proto.RegisteredEntry{
		ParentId: response.RegisteredEntry.ParentId,
		SpiffeId: response.RegisteredEntry.SpiffeId,
		Ttl:      response.RegisteredEntry.Ttl,
	}

	for _, s := range response.RegisteredEntry.SelectorList {
		selector := &proto.Selector{
			Type:  s.Type,
			Value: s.Value,
		}
		protoEntry.Selectors = append(protoEntry.Selectors, selector)
	}

	return protoEntry, nil
}