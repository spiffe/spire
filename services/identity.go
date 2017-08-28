package services

import (
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/datastore"
	"github.com/spiffe/sri/pkg/server/noderesolver"
)

//Identity service interface.
type Identity interface {
	Resolve(baseSpiffeIDs []string) (selectors map[string]*common.Selectors, err error)
	CreateEntry(baseSpiffeID string, selector *common.Selector) (err error)
}

//IdentityImpl is an implementation of the Attestation interface.
type IdentityImpl struct {
	dataStore    datastore.DataStore
	nodeResolver noderesolver.NodeResolver
}

//NewIdentityImpl creastes a new AttestationImpl.
func NewIdentityImpl(dataStore datastore.DataStore, nodeResolver noderesolver.NodeResolver) *IdentityImpl {
	return &IdentityImpl{
		dataStore:    dataStore,
		nodeResolver: nodeResolver,
	}
}

func (i *IdentityImpl) Resolve(baseSpiffeIDs []string) (selectors map[string]*common.Selectors, err error) {
	if selectors, err = i.nodeResolver.Resolve(baseSpiffeIDs); err != nil {
		return nil, err
	}
	return
}

func (i *IdentityImpl) CreateEntry(baseSpiffeID string, selector *common.Selector) (err error) {
	mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
		BaseSpiffeId: baseSpiffeID,
		Selector:     selector,
	}}
	_, err = i.dataStore.CreateNodeResolverMapEntry(mapEntryRequest)
	return
}
