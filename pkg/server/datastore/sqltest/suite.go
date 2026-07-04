package sqltest

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/test/spiretest"
)

// DataStoreUnderTest is the surface the shared suite exercises. It embeds
// RawQuerier so the raw-SQL escape hatch is part of the compile-time contract:
// an implementation missing or mis-typing any RawQuerier method fails to build
// rather than panicking mid-run on a failed type assertion.
type DataStoreUnderTest interface {
	datastore.DataStore
	io.Closer
	RawQuerier
	Configure(ctx context.Context, hclConfiguration string) error
}

// Config parameterizes the shared suite over a concrete implementation.
type Config struct {
	// NewDataStore builds a fresh, unconfigured datastore.
	NewDataStore func(log logrus.FieldLogger) DataStoreUnderTest
	// Dialect / connection strings for integration runs; empty Dialect => sqlite3.
	Dialect      string
	ConnString   string
	ROConnString string

	// ExpectedSchemaVersion is the schema version a freshly-migrated database
	// should report in its migrations table (the implementation's latest schema
	// version).
	ExpectedSchemaVersion int

	// ExpectedCodeVersion is the SPIRE code version string it should record.
	ExpectedCodeVersion string
}

// Run executes the shared datastore conformance suite against the datastore
// produced by cfg.NewDataStore.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	spiretest.Run(t, &Suite{cfg: cfg})
}
