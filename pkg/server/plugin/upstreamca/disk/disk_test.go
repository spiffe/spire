package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/spiffe/spire/test/spiretest"
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
)

var (
	ctx = context.Background()
)

func TestDisk(t *testing.T) {
	spiretest.Run(t, new(DiskSuite))
}

type DiskSuite struct {
	spiretest.Suite

	rawPlugin *DiskPlugin
	p         upstreamca.Plugin
}

func (s *DiskSuite) SetupTest() {
	p := New()

	s.rawPlugin = p
	s.LoadPlugin(builtin(p), &s.p)
	s.configure()
}

func (s *DiskSuite) configure() {
	resp, err := s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	s.Require().NoError(err)
	s.Require().Equal(&spi.ConfigureResponse{}, resp)
}

func (s *DiskSuite) TestConfigureUsingECKey() {
	err := s.configureWith("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")
	s.Require().NoError(err)
}
func (s *DiskSuite) TestConfigureUsingPKCS1Key() {
	err := s.configureWith("_test_data/keys/PKCS1/private_key.pem", "_test_data/keys/PKCS1/cert.pem")
	s.Require().NoError(err)
}

func (s *DiskSuite) TestConfigureUsingPKCS8Key() {
	err := s.configureWith("_test_data/keys/PKCS8/private_key.pem", "_test_data/keys/PKCS8/cert.pem")
	s.Require().NoError(err)
}

func (s *DiskSuite) TestConfigureUsingNonMatchingKeyAndCert() {
	err := s.configureWith("_test_data/keys/PKCS1/private_key.pem", "_test_data/keys/PKCS8/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestConfigureUsingEmptyKey() {
	err := s.configureWith("_test_data/keys/empty/private_key.pem", "_test_data/keys/empty/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestConfigureUsingEmptyCert() {
	err := s.configureWith("_test_data/keys/EC/private_key.pem", "_test_data/keys/empty/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestConfigureUsingUnknownKey() {
	err := s.configureWith("_test_data/keys/unknonw/private_key.pem", "_test_data/keys/unknonw/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestConfigureUsingBadCert() {
	err := s.configureWith("_test_data/keys/PKCS1/private_key.pem", "_test_data/keys/unknonw/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestConfigureWithMismatchedCertKey() {
	err := s.configureWith("_test_data/keys/PKCS1/private_key.pem", "_test_data/keys/EC/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestGetPluginInfo() {
	res, err := s.p.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(res)
}

func (s *DiskSuite) TestImplicitRootFromCertFile() {
	// On OSX
	// openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem
	// openssl req -x509 -new -key root_key.pem -out root_cert.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://root\nbasicConstraints=CA:true") -extensions v3
	// openssl ecparam -name prime256v1 -genkey -noout -out upstream_key.pem
	// openssl req  -new -key upstream_key.pem -out upstream_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	// openssl x509 -req -CA root_cert.pem -CAkey root_key.pem -in upstream_csr.pem -out upstream_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	// cat upstream_cert.pem root_cert.pem > upstream_and_root.pem
	require := s.Require()

	err := s.configureWith("_test_data/keys/EC/upstream_key.pem", "_test_data/keys/EC/upstream_and_root.pem")
	require.NoError(err)

	csrPEM, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	require.NoError(err)
	block, rest := pem.Decode(csrPEM)
	require.Len(rest, 0)

	resp, err := s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
	require.NoError(err)
	require.NotNil(resp)
	require.NotNil(resp.SignedCertificate)

	testCSRResp(s.T(), resp, []string{"spiffe://localhost", "spiffe://upstream"}, []string{"spiffe://root"})
}

func (s *DiskSuite) TestExplicitBundle() {
	require := s.Require()

	_, err := s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{
  "key_file_path": "_test_data/keys/EC/upstream_key.pem",
  "cert_file_path": "_test_data/keys/EC/upstream_cert.pem",
  "bundle_file_path": "_test_data/keys/EC/root_cert.pem",
  "ttl": "1h",
}`,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	require.NoError(err)

	csrPEM, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	require.NoError(err)
	block, rest := pem.Decode(csrPEM)
	require.Len(rest, 0)

	resp, err := s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
	require.NoError(err)
	require.NotNil(resp)
	require.NotNil(resp.SignedCertificate)

	testCSRResp(s.T(), resp, []string{"spiffe://localhost", "spiffe://upstream"}, []string{"spiffe://root"})
}

func (s *DiskSuite) TestBadBundleFile() {
	require := s.Require()

	_, err := s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{
  "key_file_path": "_test_data/keys/EC/upstream_key.pem",
  "cert_file_path": "_test_data/keys/EC/upstream_cert.pem",
  "bundle_file_path": "_test_data/keys/empty/cert.pem",
  "ttl": "1h",
}`,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	require.Error(err)
}

func (s *DiskSuite) TestSubmitValidCSR() {
	require := s.Require()

	const testDataDir = "_test_data/csr_valid"
	csrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(err)

	testCSR := func(csrFile os.FileInfo) {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, csrFile.Name()))
		require.NoError(err)
		block, rest := pem.Decode(csrPEM)
		require.Len(rest, 0)

		resp, err := s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.NoError(err)
		require.NotNil(resp)
		require.NotNil(resp.SignedCertificate)

		testCSRResp(s.T(), resp, []string{"spiffe://localhost"}, []string{"spiffe://local"})
	}

	for _, csrFile := range csrFiles {
		testCSR(csrFile)
	}

	// Modify the cert and key file paths. The CSR will still be
	// signed by the cached upstreamCA.
	s.rawPlugin.mtx.Lock()
	s.rawPlugin.config.CertFilePath = "invalid-file"
	s.rawPlugin.config.KeyFilePath = "invalid-file"
	s.rawPlugin.mtx.Unlock()

	for _, csrFile := range csrFiles {
		testCSR(csrFile)
	}
}

func testCSRResp(t *testing.T, resp *upstreamca.SubmitCSRResponse, expectCertChainURIs []string, expectTrustBundleURIs []string) {
	certs, err := x509.ParseCertificates(resp.SignedCertificate.CertChain)
	require.NoError(t, err)

	trustBundle, err := x509.ParseCertificates(resp.SignedCertificate.Bundle)
	require.NoError(t, err)

	for i, cert := range certs {
		assert.Equal(t, expectCertChainURIs[i], certURI(cert))
	}

	for i, cert := range trustBundle {
		assert.Equal(t, expectTrustBundleURIs[i], certURI(cert))
	}
}

func (s *DiskSuite) TestSubmitInvalidCSR() {
	require := s.Require()

	const testDataDir = "_test_data/csr_invalid"
	csrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(err)

	for _, csrFile := range csrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, csrFile.Name()))
		require.NoError(err)
		block, rest := pem.Decode(csrPEM)
		require.Len(rest, 0)

		resp, err := s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.Error(err)
		require.Nil(resp)
	}
}

func (s *DiskSuite) TestRace() {
	csr, err := ioutil.ReadFile("_test_data/csr_valid/csr_1.pem")
	s.Require().NoError(err)

	testutil.RaceTest(s.T(), func(t *testing.T) {
		s.p.Configure(ctx, &spi.ConfigureRequest{Configuration: config})
		s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr})
	})
}

func (s *DiskSuite) configureWith(keyFilePath string, certFilePath string) error {
	config, err := json.Marshal(Configuration{
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
		TTL:          "1h",
	})
	s.Require().NoError(err)

	_, err = s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: string(config),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	return err
}

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}

func TestInvalidConfigs(t *testing.T) {
	tests := []struct {
		msg               string
		inputConfig       string
		trustDomain       string
		expectErrContains string
	}{
		{
			msg:               "fail to decode",
			trustDomain:       "trust.domain",
			inputConfig:       `this is :[ invalid ^^^ hcl`,
			expectErrContains: "illegal char",
		},
		{
			msg:               "no trust domain",
			expectErrContains: "trust_domain is required",
		},
		{
			msg:         "invalid ttl",
			trustDomain: "trust.domain",
			inputConfig: `{
  "key_file_path": "path",
  "cert_file_path": "path",
  "ttl": "monday",
}`,
			expectErrContains: "invalid duration monday",
		},
	}

	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			p := New()

			_, err := p.Configure(ctx, &spi.ConfigureRequest{
				Configuration: tt.inputConfig,
				GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: tt.trustDomain},
			})
			assert.Contains(t, err.Error(), tt.expectErrContains)
		})
	}
}
