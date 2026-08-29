package sqlstore

import "github.com/spiffe/spire/pkg/server/datastore/sqltest"

var (
	_ sqltest.DataStoreUnderTest = (*Plugin)(nil)
)
