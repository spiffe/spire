package bundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeregistrationclient"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
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

	s.ds = fakedatastore.New(s.T())
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
	s.Require().Equal(`Usage of experimental bundle show (deprecated - please use "bundle show" instead):
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

	s.Require().Equal(cert1JWKS, s.stdout.String())
}

func (s *ExperimentalBundleSuite) TestSetHelp() {
	s.setCmd.Help()
	s.Require().Equal(`Usage of experimental bundle set (deprecated - please use "bundle set" instead):
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
	tmpDir := spiretest.TempDir(s.T())

	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	s.Require().NoError(ioutil.WriteFile(bundlePath, []byte(otherDomainJWKS), 0600))
	s.assertBundleSet("-id", "spiffe://otherdomain.test", "-path", bundlePath)
}

func (s *ExperimentalBundleSuite) TestListHelp() {
	s.listCmd.Help()
	s.Require().Equal(`Usage of experimental bundle list (deprecated - please use "bundle list" instead):
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
	s.Require().Equal(allBundlesJWKS, s.stdout.String())
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
	s.Require().Equal(cert2JWKS, s.stdout.String())
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
	expectedResp := &datastore.FetchBundleResponse{
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://otherdomain.test",
			RootCas: []*common.Certificate{
				{
					DerBytes: s.cert1.Raw,
				},
			},
			JwtSigningKeys: []*common.PublicKey{
				{
					PkixBytes: s.key1Pkix,
					Kid:       "KID",
				},
			},
		},
	}
	spiretest.RequireProtoEqual(s.T(), expectedResp, resp)
}

func (s *ExperimentalBundleSuite) createBundle(bundle *common.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}
