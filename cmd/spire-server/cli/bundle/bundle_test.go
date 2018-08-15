package bundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeregistrationclient"
	"github.com/stretchr/testify/suite"
)

const (
	cert1PEM = `-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4xLm9yZzANBgkqhkiG9w0BAQsFAANhAKhllc6dGydPMDpp1HcM3EHe
GWMcEIh/9knXGn+RnofPcZ7wo/NAEWE1L6KDuoBqDebYuux8FMOUF9t0vxs8scoR
A0kxWh3e9x+qgKAonawPNQjEejUNjVn5Ws9EgkQDwA==
-----END CERTIFICATE-----`
	cert2PEM = `-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4yLm9yZzANBgkqhkiG9w0BAQsFAANhAKUKjYz7/FGgaRx+UccbIwF2
ADk0ZfIYCNa7vT9UdUlP90e5la6UL7jGT65GtjPG9R2aF3Mt2vOVEfKh3cDr2q4I
kH9lL2vU0UCso2vZxSX7K3MBUCQBYCxZRZqPC7070w==
-----END CERTIFICATE-----`
)

func TestBundleCommands(t *testing.T) {
	suite.Run(t, new(BundleSuite))
}

type BundleSuite struct {
	suite.Suite

	cert1 *x509.Certificate
	cert2 *x509.Certificate

	ds                 *fakedatastore.DataStore
	registrationClient *fakeregistrationclient.Client
	stdin              *bytes.Buffer
	stdout             *bytes.Buffer
	stderr             *bytes.Buffer

	showCmd   cli.Command
	setCmd    cli.Command
	listCmd   cli.Command
	deleteCmd cli.Command
}

func (s *BundleSuite) SetupTest() {
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	s.Require().NoError(err)
	s.cert1 = cert1

	cert2, err := pemutil.ParseCertificate([]byte(cert2PEM))
	s.Require().NoError(err)
	s.cert2 = cert2

	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	s.stderr = new(bytes.Buffer)

	s.ds = fakedatastore.New()
	s.registrationClient = fakeregistrationclient.New(s.T(), "spiffe://example.org", s.ds, nil)

	testEnv := &env{
		stdin:  s.stdin,
		stdout: s.stdout,
		stderr: s.stderr,
	}
	clientMaker := func(context.Context, string) (*clients, error) {
		return &clients{
			r: s.registrationClient,
		}, nil
	}

	s.showCmd = newShowCommand(testEnv, clientMaker)
	s.setCmd = newSetCommand(testEnv, clientMaker)
	s.listCmd = newListCommand(testEnv, clientMaker)
	s.deleteCmd = newDeleteCommand(testEnv, clientMaker)
}

func (s *BundleSuite) TearDownTest() {
	// gotta close the registration client or we will leak a goroutine
	s.registrationClient.Close()
}

func (s *BundleSuite) AfterTest(suiteName, testName string) {
	s.T().Logf("SUITE: %s TEST:%s", suiteName, testName)
	s.T().Logf("STDOUT:\n%s", s.stdout.String())
	s.T().Logf("STDIN:\n%s", s.stdin.String())
	s.T().Logf("STDERR:\n%s", s.stderr.String())
}

func (s *BundleSuite) TestShowHelp() {
	s.showCmd.Help()
	s.Require().Equal(`Usage of bundle show:
  -serverAddr string
    	Address of the SPIRE server (default "localhost:8081")
`, s.stderr.String())
}

func (s *BundleSuite) TestShow() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://example.org",
		CaCerts:     s.cert1.Raw,
	})

	s.Require().Equal(0, s.showCmd.Run([]string{}))

	s.Require().Equal(s.stdout.String(), `-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4xLm9yZzANBgkqhkiG9w0BAQsFAANhAKhllc6dGydPMDpp1HcM3EHe
GWMcEIh/9knXGn+RnofPcZ7wo/NAEWE1L6KDuoBqDebYuux8FMOUF9t0vxs8scoR
A0kxWh3e9x+qgKAonawPNQjEejUNjVn5Ws9EgkQDwA==
-----END CERTIFICATE-----
`)
}

func (s *BundleSuite) TestSetHelp() {
	s.setCmd.Help()
	s.Require().Equal(`Usage of bundle set:
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -serverAddr string
    	Address of the SPIRE server (default "localhost:8081")
`, s.stderr.String())
}

func (s *BundleSuite) TestSetWithoutID() {
	rc := s.setCmd.Run([]string{})
	s.Require().Equal(1, rc)
	s.Require().Equal("id is required\n", s.stderr.String())
}

func (s *BundleSuite) TestSetWithInvalidTrustDomainID() {
	rc := s.setCmd.Run([]string{"-id", "spiffe://otherdomain.org/spire/server"})
	s.Require().Equal(1, rc)
	s.Require().Equal("\"spiffe://otherdomain.org/spire/server\" is not a valid trust domain SPIFFE ID: path is not empty\n", s.stderr.String())
}

func (s *BundleSuite) TestSetWithBadBundleData() {
	rc := s.setCmd.Run([]string{"-id", "spiffe://otherdomain.org"})
	s.Require().Equal(1, rc)
	s.Require().Equal("invalid bundle data: no PEM blocks\n", s.stderr.String())
}

func (s *BundleSuite) TestSetCreatesBundle() {
	s.stdin.WriteString(cert1PEM)
	s.assertBundleSet()
}

func (s *BundleSuite) TestSetUpdatesBundle() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://otherdomain.org",
		CaCerts:     []byte("BOGUSCERTS"),
	})
	s.stdin.WriteString(cert1PEM)
	s.assertBundleSet()
}

func (s *BundleSuite) TestSetCannotLoadBundleFromFile() {
	rc := s.setCmd.Run([]string{"-id", "spiffe://otherdomain.org", "-path", "/not/a/real/path/to/a/bundle"})
	s.Require().Equal(1, rc)
	s.Require().Equal("unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n", s.stderr.String())
}

func (s *BundleSuite) TestSetCreatesBundleFromFile() {
	tmpDir, err := ioutil.TempDir("", "spire-server-cli-test-")
	s.Require().NoError(err)
	defer os.RemoveAll(tmpDir)

	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	s.Require().NoError(ioutil.WriteFile(bundlePath, []byte(cert1PEM), 0644))
	s.assertBundleSet("-path", bundlePath)
}

func (s *BundleSuite) TestListHelp() {
	s.listCmd.Help()
	s.Require().Equal(`Usage of bundle list:
  -id string
    	SPIFFE ID of the trust domain
  -serverAddr string
    	Address of the SPIRE server (default "localhost:8081")
`, s.stderr.String())
}

func (s *BundleSuite) TestListAll() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://domain1.org",
		CaCerts:     s.cert1.Raw,
	})
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://domain2.org",
		CaCerts:     s.cert2.Raw,
	})

	s.Require().Equal(0, s.listCmd.Run([]string{}))

	s.Require().Equal(s.stdout.String(), `****************************************
* spiffe://domain1.org
****************************************
-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4xLm9yZzANBgkqhkiG9w0BAQsFAANhAKhllc6dGydPMDpp1HcM3EHe
GWMcEIh/9knXGn+RnofPcZ7wo/NAEWE1L6KDuoBqDebYuux8FMOUF9t0vxs8scoR
A0kxWh3e9x+qgKAonawPNQjEejUNjVn5Ws9EgkQDwA==
-----END CERTIFICATE-----

****************************************
* spiffe://domain2.org
****************************************
-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4yLm9yZzANBgkqhkiG9w0BAQsFAANhAKUKjYz7/FGgaRx+UccbIwF2
ADk0ZfIYCNa7vT9UdUlP90e5la6UL7jGT65GtjPG9R2aF3Mt2vOVEfKh3cDr2q4I
kH9lL2vU0UCso2vZxSX7K3MBUCQBYCxZRZqPC7070w==
-----END CERTIFICATE-----
`)
}

func (s *BundleSuite) TestListOne() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://domain1.org",
		CaCerts:     s.cert1.Raw,
	})
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://domain2.org",
		CaCerts:     s.cert2.Raw,
	})

	s.Require().Equal(0, s.listCmd.Run([]string{"-id", "spiffe://domain2.org"}))

	s.Require().Equal(s.stdout.String(), `-----BEGIN CERTIFICATE-----
MIIBazCB9qADAgECAgEBMA0GCSqGSIb3DQEBCwUAMAAwIhgPMDAwMTAxMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowADB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQDa
66N/dVJS7SG5QKfe7kNof1FazqxlIIdOUHkFP7NtsaAYl9KvRrhFvJL1cPGzUB/r
DXHya800n2N+eTD9nMqGsyURsuZ6EmH+3ALJ4MHB23Nd4M2AqP1vodXJmGfEWZ8C
AwEAAaM3MDUwDwYDVR0TAQH/BAUwAwEB/zAiBgNVHREBAf8EGDAWhhRzcGlmZmU6
Ly9kb21haW4yLm9yZzANBgkqhkiG9w0BAQsFAANhAKUKjYz7/FGgaRx+UccbIwF2
ADk0ZfIYCNa7vT9UdUlP90e5la6UL7jGT65GtjPG9R2aF3Mt2vOVEfKh3cDr2q4I
kH9lL2vU0UCso2vZxSX7K3MBUCQBYCxZRZqPC7070w==
-----END CERTIFICATE-----
`)
}

func (s *BundleSuite) TestDeleteHelp() {
	s.deleteCmd.Help()
	s.Require().Equal(`Usage of bundle delete:
  -id string
    	SPIFFE ID of the trust domain
  -serverAddr string
    	Address of the SPIRE server (default "localhost:8081")
`, s.stderr.String())
}

func (s *BundleSuite) TestDeleteWithoutID() {
	s.Require().Equal(1, s.deleteCmd.Run([]string{}))
	s.Require().Equal("id is required\n", s.stderr.String())
}

func (s *BundleSuite) TestDelete() {
	s.createBundle(&datastore.Bundle{
		TrustDomain: "spiffe://domain1.org",
		CaCerts:     s.cert1.Raw,
	})

	s.Require().Equal(0, s.deleteCmd.Run([]string{"-id", "spiffe://domain1.org"}))
	s.Require().Equal("bundle deleted.\n", s.stdout.String())

	_, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
		TrustDomain: "spiffe://domain1.org",
	})
	s.Require().EqualError(err, "no such bundle")
}

func (s *BundleSuite) assertBundleSet(extraArgs ...string) {
	rc := s.setCmd.Run(append([]string{"-id", "spiffe://otherdomain.org"}, extraArgs...))
	s.Require().Equal(0, rc)
	s.Require().Equal("bundle set.\n", s.stdout.String())

	// make sure it made it into the datastore
	resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
		TrustDomain: "spiffe://otherdomain.org",
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Bundle)
	s.Require().Equal(s.cert1.Raw, resp.Bundle.CaCerts)
}

func (s *BundleSuite) createBundle(bundle *datastore.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}
