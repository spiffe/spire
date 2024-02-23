package bundle

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var availableFormats = []string{"pretty", "json"}

func TestShowHelp(t *testing.T) {
	test := setupTest(t, newShowCommand)
	test.client.Help()

	require.Equal(t, showUsage, test.stderr.String())
}

func TestShowSynopsis(t *testing.T) {
	test := setupTest(t, newShowCommand)
	require.Equal(t, "Prints server CA bundle to stdout", test.client.Synopsis())
}

func TestShow(t *testing.T) {
	expectedShowResultJSON := `{
  "trust_domain": "spiffe://example.test",
  "x509_authorities": [
    {
      "asn1": "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U=",
      "tainted": false
    }
  ],
  "jwt_authorities": [],
  "refresh_hint": "60",
  "sequence_number": "42"
}`
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		serverErr            error
		expectedError        string
	}{
		{
			name:                 "default",
			expectedStdoutPretty: cert1PEM,
			expectedStdoutJSON:   expectedShowResultJSON,
		},
		{
			name:                 "pem",
			args:                 []string{"-format", util.FormatPEM},
			expectedStdoutPretty: cert1PEM,
			expectedStdoutJSON:   expectedShowResultJSON,
		},
		{
			name:                 "spiffe",
			args:                 []string{"-format", util.FormatSPIFFE},
			expectedStdoutPretty: cert1JWKS,
			expectedStdoutJSON:   expectedShowResultJSON,
		},
		{
			name:          "server fails",
			serverErr:     errors.New("some error"),
			expectedError: "Error: rpc error: code = Unknown desc = some error\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newShowCommand)
				test.server.err = tt.serverErr
				test.server.bundles = []*types.Bundle{{
					TrustDomain: "spiffe://example.test",
					X509Authorities: []*types.X509Certificate{
						{Asn1: test.cert1.Raw},
					},
					RefreshHint:    60,
					SequenceNumber: 42,
				},
				}
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))
				if tt.expectedError != "" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectedError, test.stderr.String())
					return
				}
				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, 0, rc)
			})
		}
	}
}

func TestSetHelp(t *testing.T) {
	test := setupTest(t, newSetCommand)
	test.client.Help()
	require.Equal(t, setUsage, test.stderr.String())
}

func TestSetSynopsis(t *testing.T) {
	test := setupTest(t, newSetCommand)
	require.Equal(t, "Creates or updates federated bundle data", test.client.Synopsis())
}

func TestSet(t *testing.T) {
	expectedSetResultJSON := `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": ""
      },
      "bundle": {
        "trust_domain": "spiffe://otherdomain.test",
        "x509_authorities": [],
        "jwt_authorities": [],
        "refresh_hint": "0",
        "sequence_number": "0"
      }
    }
  ]
}`
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	require.NoError(t, err)

	key1Pkix, err := x509.MarshalPKIXPublicKey(cert1.PublicKey)
	require.NoError(t, err)

	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedStderrPretty string
		expectedStderrJSON   string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		stdin                string
		fileData             string
		serverErr            error
		toSet                *types.Bundle
		setResponse          *bundlev1.BatchSetFederatedBundleResponse
	}{
		{
			name:                 "no id",
			expectedStderrPretty: "Error: id flag is required\n",
			expectedStderrJSON:   "Error: id flag is required\n",
		},
		{
			name:                 "invalid trust domain ID",
			expectedStderrPretty: "Error: unable to parse bundle data: no PEM blocks\n",
			expectedStderrJSON:   "Error: unable to parse bundle data: no PEM blocks\n",
			args:                 []string{"-id", "spiffe://otherdomain.test"},
		},
		{
			name:                 "invalid output format",
			stdin:                cert1PEM,
			args:                 []string{"-id", "spiffe://otherdomain.test", "-format", "invalidFormat"},
			expectedStderrPretty: "Error: invalid format: \"invalidformat\"\n",
			expectedStderrJSON:   "Error: invalid format: \"invalidformat\"\n",
		},
		{
			name:                 "invalid bundle (pem)",
			stdin:                "invalid bundle",
			args:                 []string{"-id", "spiffe://otherdomain.test"},
			expectedStderrPretty: "Error: unable to parse bundle data: no PEM blocks\n",
			expectedStderrJSON:   "Error: unable to parse bundle data: no PEM blocks\n",
		},
		{
			name:                 "invalid bundle (spiffe)",
			stdin:                "invalid bundle",
			args:                 []string{"-id", "spiffe://otherdomain.test", "-format", util.FormatSPIFFE},
			expectedStderrPretty: "Error: unable to parse to spiffe bundle: spiffebundle: unable to parse JWKS: invalid character 'i' looking for beginning of value\n",
			expectedStderrJSON:   "Error: unable to parse to spiffe bundle: spiffebundle: unable to parse JWKS: invalid character 'i' looking for beginning of value\n",
		},
		{
			name:                 "server fails",
			stdin:                cert1PEM,
			args:                 []string{"-id", "spiffe://otherdomain.test"},
			serverErr:            status.New(codes.Internal, "some error").Err(),
			expectedStderrPretty: "Error: failed to set federated bundle: rpc error: code = Internal desc = some error\n",
			expectedStderrJSON:   "Error: failed to set federated bundle: rpc error: code = Internal desc = some error\n",
		},
		{
			name:                 "failed to set",
			stdin:                cert1PEM,
			args:                 []string{"-id", "spiffe://otherdomain.test"},
			expectedStderrPretty: "Error: failed to set federated bundle: failed to set\n",
			expectedStdoutJSON:   `{"results":[{"status":{"code":13,"message":"failed to set"}}]}`,
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
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
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
		{
			name:  "set bundle (pem)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", util.FormatPEM},
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
		{
			name:  "set bundle (jwks)",
			stdin: otherDomainJWKS,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", util.FormatSPIFFE},
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
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
		{
			name:                 "invalid file name",
			expectedStderrPretty: fmt.Sprintf("Error: unable to load bundle data: open /not/a/real/path/to/a/bundle: %s\n", spiretest.PathNotFound()),
			expectedStderrJSON:   fmt.Sprintf("Error: unable to load bundle data: open /not/a/real/path/to/a/bundle: %s\n", spiretest.PathNotFound()),
			args:                 []string{"-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle"},
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
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
		{
			name:     "set from file (pem)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", util.FormatPEM},
			fileData: cert1PEM,
			toSet: &types.Bundle{
				TrustDomain: "spiffe://otherdomain.test",
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: cert1.Raw,
					},
				},
			},
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
		{
			name:     "set from file (jwks)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", util.FormatSPIFFE},
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
			setResponse: &bundlev1.BatchSetFederatedBundleResponse{
				Results: []*bundlev1.BatchSetFederatedBundleResponse_Result{
					{
						Status: &types.Status{Code: int32(codes.OK)},
						Bundle: &types.Bundle{
							TrustDomain: "spiffe://otherdomain.test",
						},
					},
				},
			},
			expectedStdoutPretty: "bundle set.",
			expectedStdoutJSON:   expectedSetResultJSON,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newSetCommand)
				test.server.expectedSetBundle = tt.toSet
				test.server.setResponse = tt.setResponse
				test.server.err = tt.serverErr
				test.stdin.WriteString(tt.stdin)
				var extraArgs []string
				if tt.fileData != "" {
					tmpDir := spiretest.TempDir(t)
					bundlePath := filepath.Join(tmpDir, "bundle_data")
					require.NoError(t, os.WriteFile(bundlePath, []byte(tt.fileData), 0600))
					extraArgs = append(extraArgs, "-path", bundlePath)
				}
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(append(args, extraArgs...)...))

				if tt.expectedStderrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectedStderrPretty, test.stderr.String())
					return
				}
				if tt.expectedStderrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectedStderrJSON, test.stderr.String())
					return
				}
				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Empty(t, test.stderr.String())
				require.Equal(t, 0, rc)
			})
		}
	}
}

func TestCountHelp(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	test.client.Help()

	require.Equal(t, countUsage, test.stderr.String())
}

func TestCountSynopsis(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	require.Equal(t, "Count bundles", test.client.Synopsis())
}

func TestCount(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		count                int
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderr       string
		serverErr            error
	}{
		{
			name:                 "all bundles",
			count:                2,
			expectedStdoutPretty: "2 bundles\n",
			expectedStdoutJSON:   `{"count":2}`,
		},
		{
			name:           "all bundles server fails",
			count:          2,
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.Error(codes.Internal, "some error"),
		},
		{
			name:                 "one bundle",
			count:                1,
			expectedStdoutPretty: "1 bundle\n",
			expectedStdoutJSON:   `{"count":1}`,
		},
		{
			name:           "one bundle server fails",
			count:          1,
			expectedStderr: "Error: rpc error: code = Internal desc = some error\n",
			serverErr:      status.Error(codes.Internal, "some error"),
		},
		{
			name:                 "no bundles",
			count:                0,
			expectedStdoutPretty: "0 bundles\n",
			expectedStdoutJSON:   `{"count":0}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
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
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expectedStderr != "" {
					require.Equal(t, tt.expectedStderr, test.stderr.String())
					require.Equal(t, 1, rc)
					return
				}
				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, 0, rc)
				require.Empty(t, test.stderr.String())
			})
		}
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t, newListCommand)
	test.client.Help()

	require.Equal(t, listUsage, test.stderr.String())
}

func TestListSynopsis(t *testing.T) {
	test := setupTest(t, newListCommand)
	require.Equal(t, "Lists federated bundle data", test.client.Synopsis())
}

func TestList(t *testing.T) {
	allBundlesResultJSON := `{
  "bundles": [
    {
      "trust_domain": "spiffe://domain1.test",
      "x509_authorities": [
        {
          "asn1": "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U=",
	  "tainted": false
        }
      ],
      "jwt_authorities": [
        {
          "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfK+wKTnKL7KFLM27lqq5DC+bxrVaH6rDV+IcCSEOeL7Cr6DdNBbFiVXnVMI8fTfTJexHG+6MPiFRRohCteTgog==",
	  "tainted": false,
          "key_id": "KID",
          "expires_at": "0"
        }
      ],
      "refresh_hint": "0",
      "sequence_number": "0"
    },
    {
      "trust_domain": "spiffe://domain2.test",
      "x509_authorities": [
        {
          "asn1": "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4=",
	  "tainted": false
        }
      ],
      "jwt_authorities": [],
      "refresh_hint": "0",
      "sequence_number": "0"
    }
  ],
  "next_page_token": ""
}`
	oneBundleResultJSON := `{
  "trust_domain": "spiffe://domain2.test",
  "x509_authorities": [
    {
      "asn1": "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4=",
       "tainted": false
    }
  ],
  "jwt_authorities": [],
  "refresh_hint": "0",
  "sequence_number": "0"
}`
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderrPretty string
		expectedStderrJSON   string
		serverErr            error
	}{
		{
			name:                 "all bundles (default)",
			expectedStdoutPretty: allBundlesPEM,
			expectedStdoutJSON:   allBundlesResultJSON,
		},
		{
			name:                 "all bundles server fails",
			expectedStderrPretty: "Error: rpc error: code = Internal desc = some error\n",
			expectedStderrJSON:   "Error: rpc error: code = Internal desc = some error\n",
			serverErr:            status.New(codes.Internal, "some error").Err(),
		},
		{
			name:                 "all bundles invalid bundle format",
			args:                 []string{"-format", "invalid"},
			expectedStderrPretty: "Error: invalid format: \"invalid\"\n",
			expectedStdoutJSON:   allBundlesResultJSON,
		},
		{
			name:                 "all bundles (pem)",
			args:                 []string{"-format", util.FormatPEM},
			expectedStdoutPretty: allBundlesPEM,
			expectedStdoutJSON:   allBundlesResultJSON,
		},
		{
			name:                 "all bundles (jwks)",
			args:                 []string{"-format", util.FormatSPIFFE},
			expectedStdoutPretty: allBundlesJWKS,
			expectedStdoutJSON:   allBundlesResultJSON,
		},
		{
			name:                 "one bundle (default)",
			args:                 []string{"-id", "spiffe://domain2.test"},
			expectedStdoutPretty: cert2PEM,
			expectedStdoutJSON:   oneBundleResultJSON,
		},
		{
			name:                 "one bundle server fails",
			args:                 []string{"-id", "spiffe://domain2.test"},
			expectedStderrPretty: "Error: rpc error: code = Internal desc = some error\n",
			expectedStderrJSON:   "Error: rpc error: code = Internal desc = some error\n",
			serverErr:            status.New(codes.Internal, "some error").Err(),
		},
		{
			name:                 "one bundle invalid bundle format",
			args:                 []string{"-id", "spiffe://domain2.test", "-format", "invalid"},
			expectedStderrPretty: "Error: invalid format: \"invalid\"\n",
			expectedStdoutJSON:   oneBundleResultJSON,
		},
		{
			name:                 "one bundle (pem)",
			args:                 []string{"-id", "spiffe://domain2.test", "-format", util.FormatPEM},
			expectedStdoutPretty: cert2PEM,
			expectedStdoutJSON:   oneBundleResultJSON,
		},
		{
			name:                 "one bundle (jwks)",
			args:                 []string{"-id", "spiffe://domain2.test", "-format", util.FormatSPIFFE},
			expectedStdoutPretty: cert2JWKS,
			expectedStdoutJSON:   oneBundleResultJSON,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
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
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expectedStderrPretty != "" && format == "pretty" {
					require.Equal(t, tt.expectedStderrPretty, test.stderr.String())
					require.Equal(t, 1, rc)
					return
				}
				if tt.expectedStderrJSON != "" && format == "json" {
					require.Equal(t, tt.expectedStderrJSON, test.stderr.String())
					require.Equal(t, 1, rc)
					return
				}
				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, 0, rc)
				require.Empty(t, test.stderr.String())
			})
		}
	}
}

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()
	require.Equal(t, deleteUsage, test.stderr.String())
}

func TestDeleteSynopsis(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	require.Equal(t, "Deletes federated bundle data", test.client.Synopsis())
}

func TestDelete(t *testing.T) {
	deleteResultJSON := `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "ok"
      },
      "trust_domain": "domain1.test"
    }
  ]
}`
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedStderrPretty string
		expectedStderrJSON   string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		deleteResults        []*bundlev1.BatchDeleteFederatedBundleResponse_Result
		mode                 bundlev1.BatchDeleteFederatedBundleRequest_Mode
		toDelete             []string
		serverErr            error
	}{
		{
			name:                 "success default mode",
			args:                 []string{"-id", "spiffe://domain1.test"},
			expectedStdoutPretty: "bundle deleted.\n",
			expectedStdoutJSON:   deleteResultJSON,
			toDelete:             []string{"spiffe://domain1.test"},
			deleteResults: []*bundlev1.BatchDeleteFederatedBundleResponse_Result{
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
			name:                 "no id",
			expectedStderrPretty: "Error: id is required\n",
			expectedStderrJSON:   "Error: id is required\n",
		},
		{
			name:                 "success RESTRICT mode",
			args:                 []string{"-id", "spiffe://domain1.test", "-mode", "restrict"},
			expectedStdoutPretty: "bundle deleted.\n",
			expectedStdoutJSON:   deleteResultJSON,
			mode:                 bundlev1.BatchDeleteFederatedBundleRequest_RESTRICT,
			toDelete:             []string{"spiffe://domain1.test"},
			deleteResults: []*bundlev1.BatchDeleteFederatedBundleResponse_Result{
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
			name:                 "success DISSOCIATE mode",
			args:                 []string{"-id", "spiffe://domain1.test", "-mode", "dissociate"},
			expectedStdoutPretty: "bundle deleted.\n",
			expectedStdoutJSON:   deleteResultJSON,
			mode:                 bundlev1.BatchDeleteFederatedBundleRequest_DISSOCIATE,
			toDelete:             []string{"spiffe://domain1.test"},
			deleteResults: []*bundlev1.BatchDeleteFederatedBundleResponse_Result{
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
			name:                 "success DELETE mode",
			args:                 []string{"-id", "spiffe://domain1.test", "-mode", "delete"},
			expectedStdoutPretty: "bundle deleted.\n",
			expectedStdoutJSON:   deleteResultJSON,
			mode:                 bundlev1.BatchDeleteFederatedBundleRequest_DELETE,
			toDelete:             []string{"spiffe://domain1.test"},
			deleteResults: []*bundlev1.BatchDeleteFederatedBundleResponse_Result{
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
			name:                 "invalid mode",
			args:                 []string{"-id", "spiffe://domain1.test", "-mode", "invalid"},
			expectedStderrPretty: "Error: unsupported mode \"invalid\"\n",
			expectedStderrJSON:   "Error: unsupported mode \"invalid\"\n",
		},
		{
			name:                 "server fails",
			args:                 []string{"-id", "spiffe://domain1.test"},
			expectedStderrPretty: "Error: failed to delete federated bundle: rpc error: code = Internal desc = some error\n",
			expectedStderrJSON:   "Error: failed to delete federated bundle: rpc error: code = Internal desc = some error\n",
			serverErr:            status.New(codes.Internal, "some error").Err(),
		},
		{
			name:     "fails to delete",
			args:     []string{"-id", "spiffe://domain1.test"},
			toDelete: []string{"spiffe://domain1.test"},
			deleteResults: []*bundlev1.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{

						Code:    int32(codes.Internal),
						Message: "some error",
					},
					TrustDomain: "domain1.test",
				},
			},
			expectedStderrPretty: "Error: failed to delete federated bundle \"domain1.test\": some error\n",
			expectedStdoutJSON:   `{"results":[{"status":{"code":13,"message":"some error"},"trust_domain":"domain1.test"}]}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newDeleteCommand)
				test.server.deleteResults = tt.deleteResults
				test.server.err = tt.serverErr
				test.server.mode = tt.mode
				test.server.toDelete = tt.toDelete
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expectedStderrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectedStderrPretty, test.stderr.String())

					return
				}
				if tt.expectedStderrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectedStderrJSON, test.stderr.String())

					return
				}
				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Empty(t, test.stderr.String())
				require.Equal(t, 0, rc)
			})
		}
	}
}

func assertOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		require.Contains(t, stdoutString, expectedStdoutPretty)
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}
