package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
)

type credentialComposerRepository struct {
	credentialcomposer.Repository
}

func (repo *credentialComposerRepository) Binder() any {
	return repo.AddCredentialComposer
}

func (repo *credentialComposerRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *credentialComposerRepository) Versions() []catalog.Version {
	return []catalog.Version{credentialComposerV1{}}
}

func (repo *credentialComposerRepository) BuiltIns() []catalog.BuiltIn {
	return nil
}

type credentialComposerV1 struct{}

func (credentialComposerV1) New() catalog.Facade { return new(credentialcomposer.V1) }
func (credentialComposerV1) Deprecated() bool    { return false }
