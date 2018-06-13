package disk

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const config = `{"trust_domain":"example.com", "ttl":"1h", "key_size":2048, "key_file_path":"_test_data/keys/private_key.pem", "cert_file_path":"_test_data/keys/cert.pem"}`

var (
	ctx = context.Background()
)

func TestDisk_Configure(t *testing.T) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	m := &diskPlugin{
		mtx: &sync.RWMutex{},
	}
	resp, err := m.Configure(ctx, pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &spi.ConfigureResponse{}, resp)
}

func TestDisk_GetPluginInfo(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")
	require.NoError(t, err)
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestDisk_SubmitValidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		assert.Len(t, rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.NoError(t, err)
		require.NotNil(t, resp)
	}
}

func TestDisk_SubmitInvalidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		assert.Len(t, rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.Error(t, err)
		require.Nil(t, resp)
	}
}

func TestDisk_race(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")
	require.NoError(t, err)

	csr, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	require.NoError(t, err)

	testutil.RaceTest(t, func(t *testing.T) {
		m.Configure(ctx, &spi.ConfigureRequest{Configuration: config})
		m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr})
	})
}

func newWithDefault(keyFilePath string, certFilePath string) (upstreamca.UpstreamCAPlugin, error) {
	config := Configuration{
		TrustDomain:  "localhost",
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
		TTL:          "1h",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m := &diskPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}
