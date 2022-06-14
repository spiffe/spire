package storage_test

import (
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/stretchr/testify/require"
)

func TestJSONFileLoadBundle(t *testing.T) {
	testLoadBundle(t, makeJSONFileStorage)
}

func TestJSONFileLoadSVID(t *testing.T) {
	testLoadSVID(t, makeJSONFileStorage)
}

func makeJSONFileStorage(t *testing.T, dir string) storage.Storage {
	sto, err := storage.JSONFile(filepath.Join(dir, "data.json"))
	require.NoError(t, err)
	return sto
}
