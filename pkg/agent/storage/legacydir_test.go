package storage_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/storage"
)

func TestLegacyDirLoadBundle(t *testing.T) {
	testLoadBundle(t, makeLegacyDirStorage)
}

func TestLegacyDirLoadSVID(t *testing.T) {
	testLoadSVID(t, makeLegacyDirStorage)
}

func makeLegacyDirStorage(t *testing.T, dir string) storage.Storage {
	return storage.LegacyDir(dir)
}
