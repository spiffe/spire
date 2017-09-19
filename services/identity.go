package services

//go:generate mockgen -source=$GOFILE -destination=identity_mock.go -package=$GOPACKAGE

import (
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/noderesolver"
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
	return i.nodeResolver.Resolve(baseSpiffeIDs)
}

func (i *IdentityImpl) CreateEntry(baseSpiffeID string, selector *common.Selector) (err error) {
	mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
		BaseSpiffeId: baseSpiffeID,
		Selector:     selector,
	}}
	_, err = i.dataStore.CreateNodeResolverMapEntry(mapEntryRequest)
	return
}
