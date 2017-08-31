package pkg

import (
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spiffe/sri/helpers/testutil"
	iface "github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/upstreamca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const config = `{"trust_domain":"example.com", "ttl":"1h", "key_size":2048, "key_file_path":"_test_data/keys/private_key.pem", "cert_file_path":"_test_data/keys/cert.pem"}`

func TestMemory_Configure(t *testing.T) {
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
	m, err := NewWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")
	require.NoError(t, err)
	res, err := m.GetPluginInfo()
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_SubmitValidCSR(t *testing.T) {
	m, err := NewWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csr, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		resp, err := m.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csr})
		require.NoError(t, err)
		require.NotNil(t, resp)
	}
}

func TestMemory_SubmitInvalidCSR(t *testing.T) {
	m, err := NewWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csr, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		resp, err := m.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csr})
		require.Error(t, err)
		require.Nil(t, resp)
	}
}

func TestMemory_race(t *testing.T) {
	m, err := NewWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")
	require.NoError(t, err)

	csr, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	require.NoError(t, err)

	testutil.RaceTest(t, func(t *testing.T) {
		m.Configure(&iface.ConfigureRequest{Configuration: config})
		m.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csr})
	})
}
