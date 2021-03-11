package bundle

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestShowHelp(t *testing.T) {
	test := setupTest(t, newShowCommand)
	test.client.Help()

	require.Equal(t, `Usage of bundle show:
  -format string
    	The format to show the bundle. Either "pem" or "spiffe". (default "pem")
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestShowSynopsis(t *testing.T) {
	test := setupTest(t, newShowCommand)
	require.Equal(t, "Prints server CA bundle to stdout", test.client.Synopsis())
}

func TestShow(t *testing.T) {
	for _, tt := range []struct {
		name          string
		args          []string
		expectedOut   string
		serverErr     error
		expectedError string
	}{
		{
			name:        "default",
			expectedOut: cert1PEM,
		},
		{
			name:        "pem",
			args:        []string{"-format", formatPEM},
			expectedOut: cert1PEM,
		},
		{
			name:        "spiffe",
			args:        []string{"-format", formatSPIFFE},
			expectedOut: cert1JWKS,
		},
		{
			name:          "server fails",
			serverErr:     errors.New("some error"),
			expectedError: "Error: rpc error: code = Unknown desc = some error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newShowCommand)
			test.server.err = tt.serverErr
			test.server.bundles = []*types.Bundle{{
				TrustDomain: "spiffe://example.test",
				X509Authorities: []*types.X509Certificate{
					{Asn1: test.cert1.Raw},
				},
				RefreshHint: 60,
			},
			}

			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
			if tt.expectedError != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectedError, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, test.stdout.String(), tt.expectedOut)
		})
	}
}

func TestSetHelp(t *testing.T) {
	test := setupTest(t, newSetCommand)
	test.client.Help()
	require.Equal(t, `Usage of bundle set:
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestSetSynopsis(t *testing.T) {
	test := setupTest(t, newSetCommand)
	require.Equal(t, "Creates or updates bundle data", test.client.Synopsis())
}

func TestSet(t *testing.T) {
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	require.NoError(t, err)

	key1Pkix, err := x509.MarshalPKIXPublicKey(cert1.PublicKey)
	require.NoError(t, err)

	for _, tt := range []struct {
		name           string
		args           []string
		expectedStderr string
		stdin          string
		fileData       string
		serverErr      error
		toSet          *types.Bundle
		setResponse    *bundle.BatchSetFederatedBundleResponse
	}{
		{
			name:           "no id",
			expectedStderr: "Error: id flag is required\n",
		},
		{
			name:           "invalid trust domain ID",
			expectedStderr: "Error: \"spiffe://otherdomain.test/spire/server\" is not a valid trust domain SPIFFE ID: path is not empty\n",
			args:           []string{"-id", "spiffe://otherdomain.test/spire/server"},
		},
		{
			name:           "invalid trust domain ID",
			expectedStderr: "Error: unable to parse bundle data: no PEM blocks\n",
			args:           []string{"-id", "spiffe://otherdomain.test"},
		},
		{
			name:           "invalid output format",
			stdin:          cert1PEM,
			args:           []string{"-id", "spiffe://otherdomain.test", "-format", "invalidFormat"},
			expectedStderr: "Error: invalid format: \"invalidformat\"\n",
		},
		{
			name:           "invalid trustdomain",
			stdin:          cert1PEM,
			args:           []string{"-id", "otherdomain test"},
			expectedStderr: "Error: \"otherdomain%20test\" is not a valid trust domain SPIFFE ID: invalid scheme\n",
		},
		{
			name:           "invalid bundle (pem)",
			stdin:          "invalid bundle",
			args:           []string{"-id", "spiffe://otherdomain.test"},
			expectedStderr: "Error: unable to parse bundle data: no PEM blocks\n",
		},
		{
			name:           "invalid bundle (spiffe)",
			stdin:          "invalid bundle",
			args:           []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
			expectedStderr: "Error: unable to parse to spiffe bundle: spiffebundle: unable to parse JWKS: invalid character 'i' looking for beginning of value\n",
		},
		{
			name:           "server fails",
			stdin:          cert1PEM,
			args:           []string{"-id", "spiffe://otherdomain.test"},
			serverErr:      status.New(codes.Internal, "some error").Err(),
			expectedStderr: "Error: failed to set federated bundle: rpc error: code = Internal desc = some error\n",
		},
		{
			name:           "failed to set",
			stdin:          cert1PEM,
			args:           []string{"-id", "spiffe://otherdomain.test"},
			expectedStderr: "Error: failed to set federated bundle: failed to set\n",
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.Internal), Message: "failed to set"},
					},
				},
			},
		},
		{
			name:  "set bundle (default)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test"},
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
		{
			name:  "set bundle (pem)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatPEM},
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
		{
			name:  "set bundle (jwks)",
			stdin: otherDomainJWKS,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
			toSet: &types.Bundle{
				TrustDomain: "otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{
						KeyId:     "KID",
						PublicKey: key1Pkix,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
		{
			name:           "invalid file name",
			expectedStderr: "Error: unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n",
			args:           []string{"-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle"},
		},
		{
			name:     "set from file (default)",
			args:     []string{"-id", "spiffe://otherdomain.test"},
			fileData: cert1PEM,
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
		{
			name:     "set from file (pem)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", formatPEM},
			fileData: cert1PEM,
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
		{
			name:     "set from file (jwks)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
			fileData: otherDomainJWKS,
			toSet: &types.Bundle{
				TrustDomain: "otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{
						KeyId:     "KID",
						PublicKey: key1Pkix,
					},
				},
			},
			setResponse: &bundle.BatchSetFederatedBundleResponse{
				Results: []*bundle.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newSetCommand)
			args := append(test.args, tt.args...)
			test.server.expectedSetBundle = tt.toSet
			test.server.setResponse = tt.setResponse
			test.server.err = tt.serverErr

			test.stdin.WriteString(tt.stdin)
			if tt.fileData != "" {
				tmpDir := spiretest.TempDir(t)
				bundlePath := filepath.Join(tmpDir, "bundle_data")
				require.NoError(t, ioutil.WriteFile(bundlePath, []byte(tt.fileData), 0600))
				args = append(args, "-path", bundlePath)
			}

			rc := test.client.Run(args)

			if tt.expectedStderr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				return
			}

			require.Empty(t, test.stderr.String())
			require.Equal(t, 0, rc)
			require.Equal(t, "bundle set.\n", test.stdout.String())
		})
	}
}

func TestCountHelp(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	test.client.Help()

	require.Equal(t, `Usage of bundle count:
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestCountSynopsis(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	require.Equal(t, "Count bundles", test.client.Synopsis())
}

func TestCount(t *testing.T) {
	for _, tt := range []struct {
		name           string
		args           []string
		count          int
		expectedStdout string
		expectedStderr string
		serverErr      error
	}{
		{
			name:           "all bundles",
			count:          2,
			expectedStdout: "2 bundles\n",
		},
		{
			name:           "all bundles server fails",
			count:          2,
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.Error(codes.Internal, "some error"),
		},
		{
			name:           "one bundle",
			count:          1,
			expectedStdout: "1 bundle\n",
		},
		{
			name:           "one bundle server fails",
			count:          1,
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.Error(codes.Internal, "some error"),
		},
		{
			name:           "no bundles",
			count:          0,
			expectedStdout: "0 bundles\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, NewCountCommandWithEnv)
			test.server.err = tt.serverErr
			bundles := []*types.Bundle{
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

			test.server.bundles = bundles[0:tt.count]
			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
			if tt.expectedStderr != "" {
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, 1, rc)
				return
			}

			require.Equal(t, 0, rc)
			require.Empty(t, test.stderr.String())
			require.Equal(t, tt.expectedStdout, test.stdout.String())
		})
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t, newListCommand)
	test.client.Help()

	require.Equal(t, `Usage of bundle list:
  -format string
    	The format to list federated bundles. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestListSynopsis(t *testing.T) {
	test := setupTest(t, newListCommand)
	require.Equal(t, "Lists federated bundle data", test.client.Synopsis())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name           string
		args           []string
		expectedStdout string
		expectedStderr string
		serverErr      error
	}{
		{
			name:           "all bundles (default)",
			expectedStdout: allBundlesPEM,
		},
		{
			name:           "all bundles server fails",
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.New(codes.Internal, "some error").Err(),
		},
		{
			name:           "all bundles invalid format",
			args:           []string{"-format", "invalid"},
			expectedStderr: "Error: invalid format: \"invalid\"\n",
		},
		{
			name:           "all bundles (pem)",
			args:           []string{"-format", formatPEM},
			expectedStdout: allBundlesPEM,
		},
		{
			name:           "all bundles (jwks)",
			args:           []string{"-format", formatSPIFFE},
			expectedStdout: allBundlesJWKS,
		},
		{
			name:           "one bundle (default)",
			args:           []string{"-id", "spiffe://domain2.test"},
			expectedStdout: cert2PEM,
		},
		{
			name:           "one bundle invalid id",
			args:           []string{"-id", "spiffe://domain2.test/host"},
			expectedStderr: "Error: \"spiffe://domain2.test/host\" is not a valid trust domain SPIFFE ID: path is not empty\n",
		},
		{
			name:           "one bundle server fails",
			args:           []string{"-id", "spiffe://domain2.test"},
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.New(codes.Internal, "some error").Err(),
		},
		{
			name:           "one bundle invalid format",
			args:           []string{"-id", "spiffe://domain2.test", "-format", "invalid"},
			expectedStderr: "Error: invalid format: \"invalid\"\n",
		},
		{
			name:           "one bundle (pem)",
			args:           []string{"-id", "spiffe://domain2.test", "-format", formatPEM},
			expectedStdout: cert2PEM,
		},
		{
			name:           "one bundle (jwks)",
			args:           []string{"-id", "spiffe://domain2.test", "-format", formatSPIFFE},
			expectedStdout: cert2JWKS,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newListCommand)
			test.server.err = tt.serverErr
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

			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
			if tt.expectedStderr != "" {
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, 1, rc)
				return
			}

			require.Equal(t, 0, rc)
			require.Empty(t, test.stderr.String())
			require.Equal(t, tt.expectedStdout, test.stdout.String())
		})
	}
}

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()
	require.Equal(t, `Usage of bundle delete:
  -id string
    	SPIFFE ID of the trust domain
  -mode string
    	Deletion mode: one of restrict, delete, or dissociate (default "restrict")
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestDeleteSynopsis(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	require.Equal(t, "Deletes bundle data", test.client.Synopsis())
}

func TestDelete(t *testing.T) {
	for _, tt := range []struct {
		name           string
		args           []string
		expectedStderr string
		expectedStdout string
		deleteResults  []*bundle.BatchDeleteFederatedBundleResponse_Result
		mode           bundle.BatchDeleteFederatedBundleRequest_Mode
		toDelete       []string
		serverErr      error
	}{
		{
			name:           "success default mode",
			args:           []string{"-id", "spiffe://domain1.test"},
			expectedStdout: "bundle deleted.\n",
			toDelete:       []string{"spiffe://domain1.test"},
			deleteResults: []*bundle.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.OK),
						Message: "ok",
					},
					TrustDomain: "domain1.test",
				},
			},
		},
		{
			name:           "no id",
			expectedStderr: "Error: id is required\n",
		},
		{
			name:           "success RESTRICT mode",
			args:           []string{"-id", "spiffe://domain1.test", "-mode", "restrict"},
			expectedStdout: "bundle deleted.\n",
			mode:           bundle.BatchDeleteFederatedBundleRequest_RESTRICT,
			toDelete:       []string{"spiffe://domain1.test"},
			deleteResults: []*bundle.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.OK),
						Message: "ok",
					},
					TrustDomain: "domain1.test",
				},
			},
		},
		{
			name:           "success DISSOCIATE mode",
			args:           []string{"-id", "spiffe://domain1.test", "-mode", "dissociate"},
			expectedStdout: "bundle deleted.\n",
			mode:           bundle.BatchDeleteFederatedBundleRequest_DISSOCIATE,
			toDelete:       []string{"spiffe://domain1.test"},
			deleteResults: []*bundle.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.OK),
						Message: "ok",
					},
					TrustDomain: "domain1.test",
				},
			},
		},
		{
			name:           "success DELETE mode",
			args:           []string{"-id", "spiffe://domain1.test", "-mode", "delete"},
			expectedStdout: "bundle deleted.\n",
			mode:           bundle.BatchDeleteFederatedBundleRequest_DELETE,
			toDelete:       []string{"spiffe://domain1.test"},
			deleteResults: []*bundle.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.OK),
						Message: "ok",
					},
					TrustDomain: "domain1.test",
				},
			},
		},
		{
			name:           "invalid mode",
			args:           []string{"-id", "spiffe://domain1.test", "-mode", "invalid"},
			expectedStderr: "Error: unsupported mode \"invalid\"\n",
		},
		{
			name:           "invalid id",
			args:           []string{"-id", "spiffe://domain1.test/host"},
			expectedStderr: "Error: \"spiffe://domain1.test/host\" is not a valid trust domain SPIFFE ID: path is not empty\n",
		},
		{
			name:           "server fails",
			args:           []string{"-id", "spiffe://domain1.test"},
			expectedStderr: "Error: failed to delete federated bundle: rpc error: code = Internal desc = some error\n",
			serverErr:      status.New(codes.Internal, "some error").Err(),
		},
		{
			name:     "fails to delete",
			args:     []string{"-id", "spiffe://domain1.test"},
			toDelete: []string{"spiffe://domain1.test"},
			deleteResults: []*bundle.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.Internal),
						Message: "some error",
					},
					TrustDomain: "domain1.test",
				},
			},
			expectedStderr: "Error: failed to delete federated bundle \"domain1.test\": some error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newDeleteCommand)
			test.server.deleteResults = tt.deleteResults
			test.server.err = tt.serverErr
			test.server.mode = tt.mode
			test.server.toDelete = tt.toDelete

			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
			if tt.expectedStderr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectedStderr, test.stderr.String())

				return
			}

			require.Empty(t, test.stderr.String())
			require.Equal(t, 0, rc)
			require.Equal(t, tt.expectedStdout, test.stdout.String())
		})
	}
}
