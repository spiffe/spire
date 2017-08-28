package services

import (
	"github.com/spiffe/sri/pkg/common"
)

//IdentityMock
type IdentityMock struct {
}

func (mock IdentityMock) Resolve(baseSpiffeIDs []string) (selectors map[string]*common.Selectors, err error) {
	return nil, nil
}

func (mock IdentityMock) CreateEntry(baseSpiffeID string, selector *common.Selector) (err error) {
	return nil
}
