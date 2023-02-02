package fakeservercatalog

import (
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
)

func New() *Catalog {
	return new(Catalog)
}

type Catalog struct {
	credentialComposerRepository
	dataStoreRepository
	keyManagerRepository
	nodeAttestorRepository
	notifierRepository
	upstreamAuthorityRepository
}

// We need distinct type names to embed in the Catalog above, since the types
// we want to actually embed are all named the same.
type credentialComposerRepository struct{ credentialcomposer.Repository }
type dataStoreRepository struct{ datastore.Repository }
type keyManagerRepository struct{ keymanager.Repository }
type nodeAttestorRepository struct{ nodeattestor.Repository }
type notifierRepository struct{ notifier.Repository }
type upstreamAuthorityRepository struct{ upstreamauthority.Repository }
