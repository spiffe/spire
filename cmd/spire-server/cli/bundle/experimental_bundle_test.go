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
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeregistrationclient"
	"github.com/stretchr/testify/suite"
)

const (
	otherDomainJWKS = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}
`
)

func TestExperimentalBundleCommands(t *testing.T) {
	suite.Run(t, new(ExperimentalBundleSuite))
}

type ExperimentalBundleSuite struct {
	suite.Suite

	cert1    *x509.Certificate
	key1Pkix []byte
	cert2    *x509.Certificate

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

func (s *ExperimentalBundleSuite) SetupTest() {
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	s.Require().NoError(err)
	s.cert1 = cert1

	key1Pkix, err := x509.MarshalPKIXPublicKey(cert1.PublicKey)
	s.Require().NoError(err)
	s.key1Pkix = key1Pkix

	cert2, err := pemutil.ParseCertificate([]byte(cert2PEM))
	s.Require().NoError(err)
	s.cert2 = cert2

	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	s.stderr = new(bytes.Buffer)

	s.ds = fakedatastore.New()
	s.registrationClient = fakeregistrationclient.New(s.T(), "spiffe://example.test", s.ds, nil)

	testEnv := &env{
		stdin:  s.stdin,
		stdout: s.stdout,
		stderr: s.stderr,
	}
	clientMaker := func(string) (*clients, error) {
		return &clients{
			r: s.registrationClient,
		}, nil
	}

	s.showCmd = newExperimentalShowCommand(testEnv, clientMaker)
	s.setCmd = newExperimentalSetCommand(testEnv, clientMaker)
	s.listCmd = newExperimentalListCommand(testEnv, clientMaker)
	s.deleteCmd = newDeleteCommand(testEnv, clientMaker)
}

func (s *ExperimentalBundleSuite) TearDownTest() {
	// gotta close the registration client or we will leak a goroutine
	s.registrationClient.Close()
}

func (s *ExperimentalBundleSuite) AfterTest(suiteName, testName string) {
	s.T().Logf("SUITE: %s TEST:%s", suiteName, testName)
	s.T().Logf("STDOUT:\n%s", s.stdout.String())
	s.T().Logf("STDIN:\n%s", s.stdin.String())
	s.T().Logf("STDERR:\n%s", s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestShowHelp() {
	s.showCmd.Help()
	s.Require().Equal(`Usage of experimental bundle show:
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestShow() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
		RefreshHint: 60,
	})

	s.Require().Equal(0, s.showCmd.Run([]string{}))

	s.Require().Equal(`{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        }
    ],
    "spiffe_refresh_hint": 60
}
`, s.stdout.String())
}

func (s *ExperimentalBundleSuite) TestSetHelp() {
	s.setCmd.Help()
	s.Require().Equal(`Usage of experimental bundle set:
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestSetCreatesBundle() {
	s.stdin.WriteString(otherDomainJWKS)
	s.assertBundleSet("-id", "spiffe://otherdomain.test")
}

func (s *ExperimentalBundleSuite) TestSetUpdatesBundle() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://otherdomain.test",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("BOGUSCERTS")},
		},
	})
	s.stdin.WriteString(otherDomainJWKS)
	s.assertBundleSet("-id", "spiffe://otherdomain.test")
}

func (s *ExperimentalBundleSuite) TestSetRequiresIDFlag() {
	rc := s.setCmd.Run([]string{})
	s.Require().Equal(1, rc)
	s.Require().Equal("id flag is required\n", s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestSetCannotLoadBundleFromFile() {
	rc := s.setCmd.Run([]string{"-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle"})
	s.Require().Equal(1, rc)
	s.Require().Equal("unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n", s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestSetCreatesBundleFromFile() {
	tmpDir, err := ioutil.TempDir("", "spire-server-cli-test-")
	s.Require().NoError(err)
	defer os.RemoveAll(tmpDir)

	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	s.Require().NoError(ioutil.WriteFile(bundlePath, []byte(otherDomainJWKS), 0644))
	s.assertBundleSet("-id", "spiffe://otherdomain.test", "-path", bundlePath)
}

func (s *ExperimentalBundleSuite) TestListHelp() {
	s.listCmd.Help()
	s.Require().Equal(`Usage of experimental bundle list:
  -id string
    	SPIFFE ID of the trust domain
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, s.stderr.String())
}

func (s *ExperimentalBundleSuite) TestListAll() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain1.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
		JwtSigningKeys: []*common.PublicKey{
			{Kid: "KID", PkixBytes: s.key1Pkix},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain2.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert2.Raw},
		},
	})

	s.Require().Equal(0, s.listCmd.Run([]string{}))

	s.Require().Equal(`****************************************
* spiffe://domain1.test
****************************************
{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}

****************************************
* spiffe://domain2.test
****************************************
{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`, s.stdout.String())
}

func (s *ExperimentalBundleSuite) TestListOne() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain1.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain2.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert2.Raw},
		},
	})

	s.Require().Equal(0, s.listCmd.Run([]string{"-id", "spiffe://domain2.test"}))

	s.Require().Equal(`{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`, s.stdout.String())
}

func (s *ExperimentalBundleSuite) assertBundleSet(args ...string) {
	rc := s.setCmd.Run(args)
	s.Require().Equal(0, rc)
	s.Require().Equal("bundle set.\n", s.stdout.String())

	// make sure it made it into the datastore
	resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
		TrustDomainId: "spiffe://otherdomain.test",
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Bundle)
	s.Require().Len(resp.Bundle.RootCas, 1)
	s.Require().Equal(s.cert1.Raw, resp.Bundle.RootCas[0].DerBytes)
	s.Require().Len(resp.Bundle.JwtSigningKeys, 1)
	s.Require().Equal("KID", resp.Bundle.JwtSigningKeys[0].Kid)
	s.Require().Equal(s.key1Pkix, resp.Bundle.JwtSigningKeys[0].PkixBytes)
}

func (s *ExperimentalBundleSuite) createBundle(bundle *common.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}

func (s *ExperimentalBundleSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	resp, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	s.Require().NoError(err)
	return resp.Entry
}
