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
	"github.com/spiffe/spire/test/spiretest"
	testutil "github.com/spiffe/spire/test/util"
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

	p upstreamca.Plugin
}

func (s *DiskSuite) SetupTest() {
	p := New()

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

func (s *DiskSuite) TestConfigureUsingUnknownKey() {
	err := s.configureWith("_test_data/keys/unknonw/private_key.pem", "_test_data/keys/unknown/cert.pem")
	s.Require().Error(err)
}

func (s *DiskSuite) TestGetPluginInfo() {
	res, err := s.p.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(res)
}

func (s *DiskSuite) TestSubmitValidCSR() {
	require := s.Require()

	const testDataDir = "_test_data/csr_valid"
	csrFiles, err := ioutil.ReadDir(testDataDir)
	require.NoError(err)

	for _, csrFile := range csrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, csrFile.Name()))
		require.NoError(err)
		block, rest := pem.Decode(csrPEM)
		require.Len(rest, 0)

		resp, err := s.p.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		require.NoError(err)
		require.NotNil(resp)
		require.NotNil(resp.SignedCertificate)

		certs, err := x509.ParseCertificates(resp.SignedCertificate.CertChain)
		require.NoError(err)
		require.Len(certs, 1)
		require.Equal("spiffe://localhost", certURI(certs[0]))

		upstreamTrustBundle, err := x509.ParseCertificates(resp.SignedCertificate.Bundle)
		require.NoError(err)
		require.Len(upstreamTrustBundle, 1)
		require.Equal("spiffe://local", certURI(upstreamTrustBundle[0]))
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
