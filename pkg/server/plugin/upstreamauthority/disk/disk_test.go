package disk

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
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

	clock     *clock.Mock
	rawPlugin *Plugin
	p         upstreamauthority.Plugin
}

func (s *DiskSuite) SetupTest() {
	s.clock = clock.NewMock(s.T())

	p := New()
	p.clock = s.clock

	// This ensures that there are only specific tests that do the verify
	// flow lowering the cost of "refreshing" all of the cert material
	// associated with the tests in this package. TODO before 2029 generate
	// all the cert and key material for tests on the fly to avoid this problem.
	p._testOnlyShouldVerify = false
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

func (s *DiskSuite) TestExplicitBundleAndVerify() {
	// On OSX
	// openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem
	//openssl req -days 3650 -x509 -new -key root_key.pem -out root_cert.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://root\nbasicConstraints=CA:true") -extensions v3
	//openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem
	//openssl req  -new -key intermediate_key.pem -out intermediate_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
	//openssl x509 -days 3650 -req -CA root_cert.pem -CAkey root_key.pem -in intermediate_csr.pem -out intermediate_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
	//openssl ecparam -name prime256v1 -genkey -noout -out upstream_key.pem
	//openssl req  -new -key upstream_key.pem -out upstream_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	//openssl x509 -days 3650 -req -CA intermediate_cert.pem -CAkey intermediate_key.pem -in upstream_csr.pem -out upstream_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	// cat upstream_cert.pem intermediate_cert.pem > upstream_and_intermediate.pem
	// This test verifies the cert chain and will start failing on May 15 2029
	require := s.Require()

	s.rawPlugin._testOnlyShouldVerify = true
	_, err := s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{
  "key_file_path": "_test_data/keys/EC/upstream_key.pem",
  "cert_file_path": "_test_data/keys/EC/upstream_cert.pem",
  "bundle_file_path": "_test_data/keys/EC/root_cert.pem",
  "ttl": "1h",
}`,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	require.Error(err, "should fail to verify as an intermediate is missing")

	_, err = s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{
  "key_file_path": "_test_data/keys/EC/upstream_key.pem",
  "cert_file_path": "_test_data/keys/EC/upstream_and_intermediate.pem",
  "bundle_file_path": "_test_data/keys/EC/root_cert.pem",
  "ttl": "1h",
}`,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	require.NoError(err)

	validSpiffeID := "spiffe://localhost"
	csr, pubKey, err := util.NewCSRTemplate(validSpiffeID)
	require.NoError(err)

	resp, err := s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: csr})
	require.NoError(err)
	require.NotNil(resp)

	testCSRResp(s.T(), resp, pubKey, []string{"spiffe://localhost", "spiffe://upstream", "spiffe://intermediate"}, []string{"spiffe://root"})
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

func (s *DiskSuite) TestNotSelfSignedWithoutBundle() {
	require := s.Require()

	_, err := s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{
  "key_file_path": "_test_data/keys/EC/upstream_key.pem",
  "cert_file_path": "_test_data/keys/EC/upstream_and_intermediate.pem",
  "ttl": "1h",
}`,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	require.Error(err)
}

func (s *DiskSuite) TestSubmitValidCSR() {
	require := s.Require()

	testCSR := func() {
		validSpiffeID := "spiffe://localhost"
		csr, pubKey, err := util.NewCSRTemplate(validSpiffeID)
		require.NoError(err)

		resp, err := s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: csr})
		require.NoError(err)
		require.NotNil(resp)

		testCSRResp(s.T(), resp, pubKey, []string{"spiffe://localhost"}, []string{"spiffe://local"})
	}

	testCSR()

	// Modify the cert and key file paths. The CSR will still be
	// signed by the cached upstreamCA.
	s.rawPlugin.mtx.Lock()
	s.rawPlugin.config.CertFilePath = "invalid-file"
	s.rawPlugin.config.KeyFilePath = "invalid-file"
	s.rawPlugin.mtx.Unlock()

	testCSR()
}

func (s *DiskSuite) TestMintX509CAUsesPreferredTTLIfSet() {
	err := s.configureWith("_test_data/keys/EC/private_key.pem", "_test_data/keys/EC/cert.pem")
	s.Require().NoError(err)

	// If the preferred TTL is set, it should be used.
	s.testCSRTTL(3600, time.Hour)

	// If the preferred TTL is zero, the default should be used.
	s.testCSRTTL(0, x509svid.DefaultUpstreamCATTL)
}

func (s *DiskSuite) testCSRTTL(preferredTTL int32, expectedTTL time.Duration) {
	validSpiffeID := "spiffe://localhost"
	csr, _, err := util.NewCSRTemplate(validSpiffeID)
	s.Require().NoError(err)

	resp, err := s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: csr, PreferredTtl: preferredTTL})
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	certs, err := x509util.RawCertsToCertificates(resp.X509CaChain)
	s.Require().NoError(err)
	s.Require().Len(certs, 1)
	s.Require().Equal(s.clock.Now().Add(expectedTTL).UTC(), certs[0].NotAfter)
}

func testCSRResp(t *testing.T, resp *upstreamauthority.MintX509CAResponse, pubKey crypto.PublicKey, expectCertChainURIs []string, expectTrustBundleURIs []string) {
	certs, err := x509util.RawCertsToCertificates(resp.X509CaChain)
	require.NoError(t, err)

	trustBundle, err := x509util.RawCertsToCertificates(resp.UpstreamX509Roots)
	require.NoError(t, err)

	for i, cert := range certs {
		assert.Equal(t, expectCertChainURIs[i], certURI(cert))
	}

	for i, cert := range trustBundle {
		assert.Equal(t, expectTrustBundleURIs[i], certURI(cert))
	}

	isEqual, err := cryptoutil.PublicKeyEqual(certs[0].PublicKey, pubKey)
	require.NoError(t, err)
	require.True(t, isEqual)
}

func (s *DiskSuite) TestSubmitInvalidCSR() {
	require := s.Require()

	invalidSpiffeIDs := []string{"invalid://localhost", "spiffe://not-trusted"}
	for _, invalidSpiffeID := range invalidSpiffeIDs {
		csr, _, err := util.NewCSRTemplate(invalidSpiffeID)
		require.NoError(err)

		resp, err := s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: csr})
		require.Error(err)
		require.Nil(resp)
	}

	invalidSequenceOfBytesAsCSR := []byte("invalid-csr")
	resp, err := s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: invalidSequenceOfBytesAsCSR})
	require.Error(err)
	require.Nil(resp)
}

func (s *DiskSuite) TestRace() {
	validSpiffeID := "spiffe://localhost"
	csr, _, err := util.NewCSRTemplate(validSpiffeID)
	s.Require().NoError(err)

	testutil.RaceTest(s.T(), func(t *testing.T) {
		// the results of these RPCs aren't important; the test is just trying
		// to get a bunch of stuff happening at once.
		_, _ = s.p.Configure(ctx, &spi.ConfigureRequest{Configuration: config})
		_, _ = s.mintX509CA(&upstreamauthority.MintX509CARequest{Csr: csr})
	})
}

func (s *DiskSuite) configureWith(keyFilePath, certFilePath string) error {
	config, err := json.Marshal(Configuration{
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
	})
	s.Require().NoError(err)

	_, err = s.p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: string(config),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	})
	return err
}

func (s *DiskSuite) TestPublishJWTKey() {
	stream, err := s.p.PublishJWTKey(context.Background(), &upstreamauthority.PublishJWTKeyRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.Require().Nil(resp)
	s.Require().EqualError(err, "rpc error: code = Unimplemented desc = upstreamauthority-disk: publishing upstream is unsupported")
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
	}

	for _, tt := range tests {
		tt := tt
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

func (s *DiskSuite) mintX509CA(req *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := s.p.MintX509CA(ctx, req)
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	// Get response and error to be returned
	response, err := stream.Recv()
	if err == nil {
		// Verify stream is closed
		_, eofErr := stream.Recv()
		s.Require().Equal(io.EOF, eofErr)
	}

	return response, err
}
