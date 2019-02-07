package disk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	config = `{
	"ttl":"1h",
	"key_file_path":"_test_data/keys/EC/private_key.pem",
	"cert_file_path":"_test_data/keys/EC/cert.pem"
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

func TestDisk_ConfigureUsingECKey(t *testing.T) {
	_, err := newWithDefault("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")
	require.NoError(t, err)
}
func TestDisk_ConfigureUsingPKCS1Key(t *testing.T) {
	_, err := newWithDefault("_test_data/keys/PKCS1/private_key.pem", "_test_data/keys/PKCS1/cert.pem")
	require.NoError(t, err)
}

func TestDisk_ConfigureUsingPKCS8Key(t *testing.T) {
	_, err := newWithDefault("_test_data/keys/PKCS8/private_key.pem", "_test_data/keys/PKCS8/cert.pem")
	require.NoError(t, err)
}

func TestDisk_ConfigureUsingEmptyKey(t *testing.T) {
	_, err := newWithDefault("_test_data/keys/empty/private_key.pem", "_test_data/keys/empty/cert.pem")
	require.Error(t, err)
}

func TestDisk_ConfigureUsingUnknownKey(t *testing.T) {
	_, err := newWithDefault("_test_data/keys/unknonw/private_key.pem", "_test_data/keys/unknown/cert.pem")
	require.Error(t, err)
}

func TestDisk_GetPluginInfo(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")
	require.NoError(t, err)
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestDisk_SubmitValidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")

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

		upstreamTrustBundle, err := x509.ParseCertificates(resp.SignedCertificate.Bundle)
		require.NoError(t, err)
		require.Len(t, upstreamTrustBundle, 1)
		require.Equal(t, "spiffe://local", certURI(upstreamTrustBundle[0]))
	}
}

func TestDisk_SubmitInvalidCSR(t *testing.T) {
	m, err := newWithDefault("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")

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
	m, err := newWithDefault("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")
	require.NoError(t, err)

	csr, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	require.NoError(t, err)

	testutil.RaceTest(t, func(t *testing.T) {
		m.Configure(ctx, &spi.ConfigureRequest{Configuration: config})
		m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr})
	})
}

func TestDisk_ParsePrivateKeyParsesEC(t *testing.T) {
	key, err := parsePrivateKey("_test_data/keys/EC/private_key.pem")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, key)
}

func TestDisk_ParsePrivateKeyParsesPKCS1(t *testing.T) {
	key, err := parsePrivateKey("_test_data/keys/PKCS1/private_key.pem")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, key)
}

func TestDisk_ParsePrivateKeyParsesPKCS8(t *testing.T) {
	key, err := parsePrivateKey("_test_data/keys/PKCS8/private_key.pem")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, key)
}
func TestDisk_ParsePrivateKeyFailsIfKeyFormatIsUnknown(t *testing.T) {
	key, err := parsePrivateKey("_test_data/keys/unknown/private_key.pem")
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestDisk_ParsePrivateKeyFailsIfKeyIsEmpty(t *testing.T) {
	key, err := parsePrivateKey("_test_data/keys/empty/private_key.pem")
	require.Error(t, err)
	assert.Nil(t, key)
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
