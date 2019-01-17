package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

const (
	config = `{
	"ttl":"1h",
	"key_file_path":"_test_data/keys/private_key.pem",
	"cert_file_path":"_test_data/keys/cert.pem"
}`
	trustDomain = "example.com"
)

var (
	ctx = context.Background()
)

func TestDisk_Configure(t *testing.T) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain},
	}

	m := New()
	resp, err := m.Configure(ctx, pluginConfig)
	require.NoError(t, err)
	require.Equal(t, &spi.ConfigureResponse{}, resp)
}

func TestDisk_GetPluginInfo(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")
	require.NoError(t, err)
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestDisk_SubmitValidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		require.Len(t, rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.SignedCertificate)

		certs, err := x509.ParseCertificates(resp.SignedCertificate.CertChain)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		require.Equal(t, "spiffe://localhost", certURI(certs[0]))

		upstreamTrustBundle, err := x509.ParseCertificates(resp.SignedCertificate.UpstreamTrustBundle)
		require.NoError(t, err)
		require.Len(t, upstreamTrustBundle, 1)
		require.Equal(t, "spiffe://local", certURI(upstreamTrustBundle[0]))
	}
}

func TestDisk_SubmitInvalidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/private_key.pem", "_test_data/keys/cert.pem")

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(t, err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		require.NoError(t, err)
		block, rest := pem.Decode(csrPEM)
		require.Len(t, rest, 0)

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

func newWithDefault(keyFilePath string, certFilePath string) (upstreamca.Plugin, error) {
	config := Configuration{
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
		TTL:          "1h",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	m := New()
	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}
