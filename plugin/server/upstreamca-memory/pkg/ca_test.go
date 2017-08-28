package pkg

import (
	"io/ioutil"
	"sync"
	"testing"

	iface "github.com/spiffe/sri/pkg/common/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
)

func TestMemory_Configure(t *testing.T) {
	config := `{"trust_domain":"example.com", "ttl":3600000, "key_size":2048}`
	pluginConfig := &iface.ConfigureRequest{
		Configuration: config,
	}

	m := &memoryPlugin{
		mtx: &sync.RWMutex{},
	}
	resp, err := m.Configure(pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &iface.ConfigureResponse{}, resp)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)
	res, err := m.GetPluginInfo()
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_SubmitValidCSR(t *testing.T) {
	m, err := NewWithDefault()

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csr, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		resp, err := m.SubmitCSR(csr)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}
}

func TestMemory_SubmitInvalidCSR(t *testing.T) {
	m, err := NewWithDefault()

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csr, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		resp, err := m.SubmitCSR(csr)
		require.Error(t, err)
		require.Nil(t, resp)
	}
}
