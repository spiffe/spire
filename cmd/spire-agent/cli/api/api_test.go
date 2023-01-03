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
)

var availableFormats = []string{"pretty", "json"}

const (
	encodedJTW1 = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImdWeVU1QzJFSm5lU3pHS3BMVmFMQllCNkdjTERLQlJjIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiYXVkMSJdLCJleHAiOjE2NzI3NjU2ODgsImlhdCI6MTY3Mjc2NTM4OCwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvbXlzZXJ2aWNlIn0.mCB3rREoOgH_yYddyVYc6vGeOACv2tjPmCoG_yxxhDkUlJfnmMsOvrnjK5nm1EFZAOIouNLYBRZk-waP31250w"
	encodedJTW2 = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImdWeVU1QzJFSm5lU3pHS3BMVmFMQllCNkdjTERLQlJjIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiYXVkMSJdLCJleHAiOjE2NzI3Njg4NzEsImlhdCI6MTY3Mjc2ODU3MSwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvbXlzZXJ2aWNlIn0.qV4jJJ4QmmuiW2nHv-o_7-RC21auGS1oU4DQkuhHpe4k2YRnnZ4A5OnjB_13p57niXeNopr-BuKMb9mP2BM9bg"

	bundleJWKS = `{
    "keys": [
        {
            "kty": "EC",
            "kid": "gVyU5C2EJneSzGKpLVaLBYB6GcLDKBRc",
            "crv": "P-256",
            "x": "oQJPipZrnNI1zknPGO4_j0K9yE6-SKlsd34KaknbHa8",
            "y": "2BuwqNOVko1sfxZEY2BbtvhFpBg-i5su-ZvieoZTRNM"
        }
    ]
}`
)

func TestFetchJWTCommand(t *testing.T) {
	tests := []struct {
		name                 string
		args                 []string
		fakeRequests         []*fakeworkloadapi.FakeRequest
		expectedStderr       string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedCode         int
	}{
		{
			name: "success fetching jwt with bundles",
			args: []string{"-audience", "audience1", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{
						Bundles: map[string][]byte{
							"spiffe://domain1.test": []byte(bundleJWKS),
							"spiffe://domain2.test": []byte(bundleJWKS),
						},
					},
				},
				{
					Req: &workload.JWTSVIDRequest{
						Audience: []string{"audience1"},
						SpiffeId: "spiffe://domain1.test",
					},
					Resp: &workload.JWTSVIDResponse{
						Svids: []*workload.JWTSVID{
							{
								SpiffeId: "spiffe://domain1.test",
								// Svid is a Encoded JWT using JWS Compact Serialization
								Svid: encodedJTW1,
							},
							{
								SpiffeId: "spiffe://domain2.test",
								// Svid is a Encoded JWT using JWS Compact Serialization
								Svid: encodedJTW2,
							},
						},
					},
				},
			},
			expectedStdoutPretty: fmt.Sprintf(`token(spiffe://domain1.test):
	%s
token(spiffe://domain2.test):
	%s
bundle(spiffe://domain1.test):
	%s
bundle(spiffe://domain2.test):
	%s
`, encodedJTW1, encodedJTW2, bundleJWKS, bundleJWKS),
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
]`, encodedJTW1, encodedJTW2, base64.StdEncoding.EncodeToString([]byte(bundleJWKS)), base64.StdEncoding.EncodeToString([]byte(bundleJWKS))),
			expectedCode: 0,
		},
		{
			name: "fail with error fetching bundles",
			args: []string{"-audience", "audience1", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req:  &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{},
					Err:  errors.New("error fetching bundles"),
				},
			},
			expectedStderr: "rpc error: code = Unknown desc = error fetching bundles\n",
			expectedCode:   0,
		},
		{
			name: "fail with error fetching svid",
			args: []string{"-audience", "audience1", "-spiffeID", "spiffe://domain1.test"},
			fakeRequests: []*fakeworkloadapi.FakeRequest{
				{
					Req: &workload.JWTBundlesRequest{},
					Resp: &workload.JWTBundlesResponse{
						Bundles: map[string][]byte{
							"spiffe://domain1.test": []byte(bundleJWKS),
						},
					},
				},
				{
					Req: &workload.JWTSVIDRequest{
						Audience: []string{"audience1"},
						SpiffeId: "spiffe://domain1.test",
					},
					Resp: &workload.JWTSVIDResponse{},
					Err:  errors.New("error fetching svid"),
				},
			},
			expectedStderr: "rpc error: code = Unknown desc = error fetching svid\n",
			expectedCode:   0,
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

				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				assert.Empty(t, test.stderr.String())
				assert.Equal(t, tt.expectedCode, rc)
			})
		}
	}
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
		expectedCode         int
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

				assertOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				assert.Empty(t, test.stderr.String())
				assert.Equal(t, tt.expectedCode, rc)

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

func TestValidateJWTCommand(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "test",
		},
	}
	for _, tt := range tests {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
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

func assertOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		if expectedStdoutPretty != "" {
			fmt.Printf("expectedStdoutPretty: %s", expectedStdoutPretty)
			require.Contains(t, stdoutString, expectedStdoutPretty)
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
