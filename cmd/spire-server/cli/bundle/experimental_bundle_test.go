package bundle

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestExperimentalShowHelp(t *testing.T) {
	test := setupTest(t, newExperimentalShowCommand)
	test.client.Help()
	require.Equal(t, `Usage of experimental bundle show (deprecated - please use "bundle show" instead):
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.stderr.String())
}

func TestExperimentalShowSynopsis(t *testing.T) {
	test := setupTest(t, newExperimentalShowCommand)
	require.Equal(t, `Prints server CA bundle to stdout. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle show" command.`,
		test.client.Synopsis())
}

func TestExperimentalShow(t *testing.T) {
	test := setupTest(t, newExperimentalShowCommand)
	test.server.bundles = []*types.Bundle{
		{
			TrustDomain: "spiffe://example.test",
			X509Authorities: []*types.X509Certificate{
				{Asn1: test.cert1.Raw},
			},
			RefreshHint: 60,
		},
	}

	require.Equal(t, 0, test.client.Run(test.args))
	require.Equal(t, cert1JWKS, test.stdout.String())
}

func TestExperientalSetHelp(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)
	test.client.Help()
	require.Equal(t, `Usage of experimental bundle set (deprecated - please use "bundle set" instead):
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.stderr.String())
}

func TestExperientalSetSynopsis(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)
	require.Equal(t, `Creates or updates bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle set" command.`,
		test.client.Synopsis())
}

func TestExperimentalSetBundle(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)

	test.stdin.WriteString(otherDomainJWKS)
	test.server.expectedSetBundle = &types.Bundle{
		TrustDomain: "otherdomain.test",
		X509Authorities: []*types.X509Certificate{
			{
				Asn1: test.cert1.Raw,
			},
		},
		JwtAuthorities: []*types.JWTKey{
			{
				PublicKey: test.key1Pkix,
				KeyId:     "KID",
			},
		},
	}
	test.server.setResponse = &bundle.BatchSetFederatedBundleResponse{
		Results: []*bundle.BatchSetFederatedBundleResponse_Result{
			{
				Status: &types.Status{Code: int32(codes.OK)},
				Bundle: &types.Bundle{
					TrustDomain: "spiffe://otherdomain.test",
				},
			},
		},
	}
	args := append(test.args, "-id", "spiffe://otherdomain.test")
	test.assertBundleSet(t, args...)
}

func TestExperimentalSetRequiresIDFlag(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)

	rc := test.client.Run(test.args)
	require.Equal(t, 1, rc)
	require.Equal(t, "Error: id flag is required\n", test.stderr.String())
}

func TestExperimentalSetCannotLoadBundleFromFile(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)
	rc := test.client.Run(append(test.args, "-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle"))
	require.Equal(t, 1, rc)
	require.Equal(t, "Error: unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n", test.stderr.String())
}

func TestExperimentalSetBundleFromFile(t *testing.T) {
	test := setupTest(t, newExperimentalSetCommand)
	tmpDir := spiretest.TempDir(t)

	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	require.NoError(t, ioutil.WriteFile(bundlePath, []byte(otherDomainJWKS), 0600))
	args := append(test.args, "-id", "spiffe://otherdomain.test", "-path", bundlePath)

	test.server.expectedSetBundle = &types.Bundle{
		TrustDomain: "otherdomain.test",
		X509Authorities: []*types.X509Certificate{
			{
				Asn1: test.cert1.Raw,
			},
		},
		JwtAuthorities: []*types.JWTKey{
			{
				PublicKey: test.key1Pkix,
				KeyId:     "KID",
			},
		},
	}
	test.server.setResponse = &bundle.BatchSetFederatedBundleResponse{
		Results: []*bundle.BatchSetFederatedBundleResponse_Result{
			{
				Status: &types.Status{Code: int32(codes.OK)},
				Bundle: &types.Bundle{
					TrustDomain: "spiffe://otherdomain.test",
				},
			},
		},
	}
	test.assertBundleSet(t, args...)
}

func TestExperientalListHelp(t *testing.T) {
	test := setupTest(t, newExperimentalListCommand)
	test.client.Help()
	require.Equal(t, `Usage of experimental bundle list (deprecated - please use "bundle list" instead):
  -id string
    	SPIFFE ID of the trust domain
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.stderr.String())
}

func TestExperientalListSynopsis(t *testing.T) {
	test := setupTest(t, newExperimentalListCommand)
	require.Equal(t, `Lists bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle list" command.`,
		test.client.Synopsis())
}

func TestExperimentalListAll(t *testing.T) {
	test := setupTest(t, newExperimentalListCommand)

	test.server.bundles = []*types.Bundle{
		{
			TrustDomain: "spiffe://domain1.test",
			X509Authorities: []*types.X509Certificate{
				{Asn1: test.cert1.Raw},
			},
			JwtAuthorities: []*types.JWTKey{
				{KeyId: "KID", PublicKey: test.key1Pkix},
			},
		},
		{
			TrustDomain: "spiffe://domain2.test",
			X509Authorities: []*types.X509Certificate{
				{Asn1: test.cert2.Raw},
			},
		},
	}

	require.Equal(t, 0, test.client.Run(test.args))
	require.Equal(t, allBundlesJWKS, test.stdout.String())
}

func TestExperimentalListOne(t *testing.T) {
	test := setupTest(t, newExperimentalListCommand)
	test.server.bundles = []*types.Bundle{
		{
			TrustDomain: "spiffe://domain1.test",
			X509Authorities: []*types.X509Certificate{
				{Asn1: test.cert1.Raw},
			},
		},
		{
			TrustDomain: "spiffe://domain2.test",
			X509Authorities: []*types.X509Certificate{
				{Asn1: test.cert2.Raw},
			},
		},
	}

	require.Equal(t, 0, test.client.Run(append(test.args, "-id", "spiffe://domain2.test")))
	require.Equal(t, cert2JWKS, test.stdout.String())
}
