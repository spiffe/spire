package api

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/fakes/fakeworkloadapi"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var availableFormats = []string{"pretty", "json"}

func TestFetchJWTCommandHelp(t *testing.T) {
	test := setupTest(t, newFetchJWTCommandWithEnv)
	test.cmd.Help()
	require.Equal(t, fetchJWTUsage, test.stderr.String())
}

func TestFetchJWTCommandSynopsis(t *testing.T) {
	test := setupTest(t, newFetchJWTCommandWithEnv)
	require.Equal(t, "Fetches a JWT SVID from the Workload API", test.cmd.Synopsis())
}

func TestFetchJWTCommand(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	encodedSvid1 := ca.CreateJWTSVID(spiffeid.RequireFromString("spiffe://domain1.test"), []string{"foo"}).Marshal()
	encodedSvid2 := ca.CreateJWTSVID(spiffeid.RequireFromString("spiffe://domain2.test"), []string{"foo"}).Marshal()
	bundleJWKSBytes, err := ca.JWTBundle().Marshal()
	require.NoError(t, err)

	tests := []struct {
		name                 string
		args                 []string
		fakeRequests         []*fakeworkloadapi.FakeRequest
		expectedStderr       string
		expectedStdoutPretty []string
		expectedStdoutJSON   string
	}{
		{
			name: "success fetching jwt with bundles",
			args: []string{"-audience", "foo", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{
						Bundles: map[string][]byte{
							"spiffe://domain1.test": bundleJWKSBytes,
							"spiffe://domain2.test": bundleJWKSBytes,
						},
					},
				},
				{
					Req: &workload.JWTSVIDRequest{
						Audience: []string{"foo"},
						SpiffeId: "spiffe://domain1.test",
					},
					Resp: &workload.JWTSVIDResponse{
						Svids: []*workload.JWTSVID{
							{
								SpiffeId: "spiffe://domain1.test",
								Svid:     encodedSvid1,
							},
							{
								SpiffeId: "spiffe://domain2.test",
								Svid:     encodedSvid2,
							},
						},
					},
				},
			},
			expectedStdoutPretty: []string{
				fmt.Sprintf("token(spiffe://domain1.test):\n\t%s", encodedSvid1),
				fmt.Sprintf("token(spiffe://domain2.test):\n\t%s", encodedSvid2),
				fmt.Sprintf("bundle(spiffe://domain1.test):\n\t%s", bundleJWKSBytes),
				fmt.Sprintf("bundle(spiffe://domain2.test):\n\t%s", bundleJWKSBytes),
			},
			expectedStdoutJSON: fmt.Sprintf(`[
  {
    "svids": [
      {
        "spiffe_id": "spiffe://domain1.test",
        "svid": "%s"
      },
      {
        "spiffe_id": "spiffe://domain2.test",
        "svid": "%s"
      }
    ]
  },
  {
    "bundles": {
      "spiffe://domain1.test": "%s",
      "spiffe://domain2.test": "%s"
    }
  }
]`, encodedSvid1, encodedSvid2, base64.StdEncoding.EncodeToString(bundleJWKSBytes), base64.StdEncoding.EncodeToString(bundleJWKSBytes)),
		},
		{
			name: "fail with error fetching bundles",
			args: []string{"-audience", "foo", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req:  &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{},
					Err:  errors.New("error fetching bundles"),
				},
			},
			expectedStderr: "rpc error: code = Unknown desc = error fetching bundles\n",
		},
		{
			name: "fail with error fetching svid",
			args: []string{"-audience", "foo", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{
						Bundles: map[string][]byte{
							"spiffe://domain1.test": bundleJWKSBytes,
						},
					},
				},
				{
					Req: &workload.JWTSVIDRequest{
						Audience: []string{"foo"},
						SpiffeId: "spiffe://domain1.test",
					},
					Resp: &workload.JWTSVIDResponse{},
					Err:  errors.New("error fetching svid"),
				},
			},
			expectedStderr: "rpc error: code = Unknown desc = error fetching svid\n",
		},
		{
			name:           "fail when audience is not provided",
			expectedStderr: "audience must be specified\n",
		},
	}

	for _, tt := range tests {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newFetchJWTCommandWithEnv, tt.fakeRequests...)
				args := tt.args
				args = append(args, "-output", format)

				rc := test.cmd.Run(test.args(args...))

				if tt.expectedStderr != "" {
					assert.Equal(t, 1, rc)
					assert.Equal(t, tt.expectedStderr, test.stderr.String())
					return
				}

				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutJSON, tt.expectedStdoutPretty...)
				assert.Empty(t, test.stderr.String())
				assert.Equal(t, 0, rc)
			})
		}
	}
}

func TestFetchX509CommandHelp(t *testing.T) {
	test := setupTest(t, newFetchX509Command)
	test.cmd.Help()
	require.Equal(t, fetchX509Usage, test.stderr.String())
}

func TestFetchX509CommandSynopsis(t *testing.T) {
	test := setupTest(t, newFetchX509Command)
	require.Equal(t, "Fetches X509 SVIDs from the Workload API", test.cmd.Synopsis())
}

func TestFetchX509Command(t *testing.T) {
	testDir := t.TempDir()
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromString("spiffe://example.org/foo"))

	tests := []struct {
		name                 string
		args                 []string
		fakeRequests         []*fakeworkloadapi.FakeRequest
		expectedStderr       string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedFileResult   bool
	}{
		{
			name: "success fetching x509 svid",
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.X509SVIDRequest{},
					Resp: &workload.X509SVIDResponse{
						Svids: []*workload.X509SVID{
							{
								SpiffeId:    svid.ID.String(),
								X509Svid:    x509util.DERFromCertificates(svid.Certificates),
								X509SvidKey: pkcs8FromSigner(t, svid.PrivateKey),
								Bundle:      x509util.DERFromCertificates(ca.Bundle().X509Authorities()),
							},
						},
						Crl:              [][]byte{},
						FederatedBundles: map[string][]byte{},
					},
				},
			},
			expectedStdoutPretty: fmt.Sprintf(`
SPIFFE ID:		spiffe://example.org/foo
SVID Valid After:	%v
SVID Valid Until:	%v
CA #1 Valid After:	%v
CA #1 Valid Until:	%v
`,
				svid.Certificates[0].NotBefore,
				svid.Certificates[0].NotAfter,
				ca.Bundle().X509Authorities()[0].NotBefore,
				ca.Bundle().X509Authorities()[0].NotAfter,
			),
			expectedStdoutJSON: fmt.Sprintf(`{
  "crl": [],
  "federated_bundles": {},
  "svids": [
    {
      "bundle": "%s",
      "spiffe_id": "spiffe://example.org/foo",
      "x509_svid": "%s",
      "x509_svid_key": "%s"
    }
  ]
}`,
				base64.StdEncoding.EncodeToString(x509util.DERFromCertificates(ca.Bundle().X509Authorities())),
				base64.StdEncoding.EncodeToString(x509util.DERFromCertificates(svid.Certificates)),
				base64.StdEncoding.EncodeToString(pkcs8FromSigner(t, svid.PrivateKey)),
			),
		},
		{
			name: "success fetching x509 and writing to file",
			args: []string{"-write", testDir},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.X509SVIDRequest{},
					Resp: &workload.X509SVIDResponse{
						Svids: []*workload.X509SVID{
							{
								SpiffeId:    svid.ID.String(),
								X509Svid:    x509util.DERFromCertificates(svid.Certificates),
								X509SvidKey: pkcs8FromSigner(t, svid.PrivateKey),
								Bundle:      x509util.DERFromCertificates(ca.Bundle().X509Authorities()),
							},
						},
						Crl:              [][]byte{},
						FederatedBundles: map[string][]byte{},
					},
				},
			},
			expectedStdoutPretty: fmt.Sprintf(`
SPIFFE ID:		spiffe://example.org/foo
SVID Valid After:	%v
SVID Valid Until:	%v
CA #1 Valid After:	%v
CA #1 Valid Until:	%v

Writing SVID #0 to file %s
Writing key #0 to file %s
Writing bundle #0 to file %s
`,
				svid.Certificates[0].NotBefore,
				svid.Certificates[0].NotAfter,
				ca.Bundle().X509Authorities()[0].NotBefore,
				ca.Bundle().X509Authorities()[0].NotAfter,
				fmt.Sprintf("%s/svid.0.pem.", testDir),
				fmt.Sprintf("%s/svid.0.key.", testDir),
				fmt.Sprintf("%s/bundle.0.pem.", testDir),
			),
			expectedStdoutJSON: fmt.Sprintf(`{
  "crl": [],
  "federated_bundles": {},
  "svids": [
    {
      "bundle": "%s",
      "spiffe_id": "spiffe://example.org/foo",
      "x509_svid": "%s",
      "x509_svid_key": "%s"
    }
  ]
}`,
				base64.StdEncoding.EncodeToString(x509util.DERFromCertificates(ca.Bundle().X509Authorities())),
				base64.StdEncoding.EncodeToString(x509util.DERFromCertificates(svid.Certificates)),
				base64.StdEncoding.EncodeToString(pkcs8FromSigner(t, svid.PrivateKey)),
			),
			expectedFileResult: true,
		},
		{
			name: "fails fetching svid",
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req:  &workload.X509SVIDRequest{},
					Resp: &workload.X509SVIDResponse{},
					Err:  errors.New("error fetching svid"),
				},
			},
			expectedStderr: "rpc error: code = Unknown desc = error fetching svid\n",
		},
	}
	for _, tt := range tests {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newFetchX509Command, tt.fakeRequests...)
				args := tt.args
				args = append(args, "-output", format)

				rc := test.cmd.Run(test.args(args...))

				if tt.expectedStderr != "" {
					assert.Equal(t, 1, rc)
					assert.Equal(t, tt.expectedStderr, test.stderr.String())
					return
				}

				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutJSON, tt.expectedStdoutPretty)
				assert.Empty(t, test.stderr.String())
				assert.Equal(t, 0, rc)

				if tt.expectedFileResult && format == "pretty" {
					content, err := os.ReadFile(filepath.Join(testDir, "svid.0.pem"))
					assert.NoError(t, err)
					assert.Equal(t, pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: svid.Certificates[0].Raw,
					}), content)

					content, err = os.ReadFile(filepath.Join(testDir, "svid.0.key"))
					assert.NoError(t, err)
					assert.Equal(t, string(pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: pkcs8FromSigner(t, svid.PrivateKey),
					})), string(content))

					content, err = os.ReadFile(filepath.Join(testDir, "bundle.0.pem"))
					assert.NoError(t, err)
					assert.Equal(t, pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: ca.Bundle().X509Authorities()[0].Raw,
					}), content)
				}
			})
		}
	}
}

func TestValidateJWTCommandHelp(t *testing.T) {
	test := setupTest(t, newValidateJWTCommand)
	test.cmd.Help()
	require.Equal(t, validateJWTUsage, test.stderr.String())
}

func TestValidateJWTCommandSynopsis(t *testing.T) {
	test := setupTest(t, newValidateJWTCommand)
	require.Equal(t, "Validates a JWT SVID", test.cmd.Synopsis())
}

func TestValidateJWTCommand(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	encodedSvid := ca.CreateJWTSVID(spiffeid.RequireFromString("spiffe://domain1.test"), []string{"foo"}).Marshal()

	tests := []struct {
		name                 string
		args                 []string
		fakeRequests         []*fakeworkloadapi.FakeRequest
		expectedStderr       string
		expectedStdoutPretty string
		expectedStdoutJSON   string
	}{
		{
			name: "valid svid",
			args: []string{"-audience", "foo", "-svid", encodedSvid},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.ValidateJWTSVIDRequest{
						Audience: "foo",
						Svid:     encodedSvid,
					},
					Resp: &workload.ValidateJWTSVIDResponse{
						SpiffeId: "spiffe://example.org/foo",
						Claims: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"aud": {
									Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
										Values: []*structpb.Value{{Kind: &structpb.Value_StringValue{StringValue: "foo"}}},
									},
									},
								},
							},
						},
					},
				},
			},
			expectedStdoutPretty: `SVID is valid.
SPIFFE ID : spiffe://example.org/foo
Claims    : {"aud":["foo"]}`,
			expectedStdoutJSON: `{
  "claims": {
    "aud": [
      "foo"
    ]
  },
  "spiffe_id": "spiffe://example.org/foo"
}`,
		},
		{
			name: "invalid svid",
			args: []string{"-audience", "invalid", "-svid", "invalid"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.ValidateJWTSVIDRequest{
						Audience: "foo",
						Svid:     encodedSvid,
					},
					Resp: &workload.ValidateJWTSVIDResponse{},
					Err:  status.Error(codes.InvalidArgument, "invalid svid"),
				},
			},
			expectedStderr: "SVID is not valid: invalid svid\n",
		},
		{
			name:           "fail when audience is not provided",
			expectedStderr: "audience must be specified\n",
		},
		{
			name:           "fail when svid is not provided",
			args:           []string{"-audience", "foo"},
			expectedStderr: "svid must be specified\n",
		},
	}
	for _, tt := range tests {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newValidateJWTCommand, tt.fakeRequests...)
				args := tt.args
				args = append(args, "-output", format)

				rc := test.cmd.Run(test.args(args...))

				if tt.expectedStderr != "" {
					assert.Equal(t, 1, rc)
					assert.Equal(t, tt.expectedStderr, test.stderr.String())
					return
				}

				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutJSON, tt.expectedStdoutPretty)
				assert.Empty(t, test.stderr.String())
				assert.Equal(t, 0, rc)
			})
		}
	}
}

func setupTest(t *testing.T, newCmd func(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command, requests ...*fakeworkloadapi.FakeRequest) *apiTest {
	workloadAPIServer := fakeworkloadapi.New(t, requests...)

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, workloadAPIServer)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	cmd := newCmd(&commoncli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}, newWorkloadClient)

	test := &apiTest{
		addr:        common.GetAddr(addr),
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
		workloadAPI: workloadAPIServer,
		cmd:         cmd,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type apiTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	addr        string
	workloadAPI *fakeworkloadapi.WorkloadAPI

	cmd cli.Command
}

func (s *apiTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", s.stdout.String())
	t.Logf("STDIN:\n%s", s.stdin.String())
	t.Logf("STDERR:\n%s", s.stderr.String())
}

func (s *apiTest) args(extra ...string) []string {
	return append([]string{common.AddrArg, s.addr}, extra...)
}

func assertOutputBasedOnFormat(t *testing.T, format, stdoutString, expectedStdoutJSON string, expectedStdoutPretty ...string) {
	switch format {
	case "pretty":
		if len(expectedStdoutPretty) > 0 {
			for _, expected := range expectedStdoutPretty {
				require.Contains(t, stdoutString, expected)
			}
		} else {
			require.Empty(t, stdoutString)
		}
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}

func pkcs8FromSigner(t *testing.T, key crypto.Signer) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return keyBytes
}
