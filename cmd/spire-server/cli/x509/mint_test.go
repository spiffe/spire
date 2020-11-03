package x509

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	svidpb "github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const (
	expectedUsage = `Usage of x509 mint:
  -dns value
    	DNS name that will be included in SVID. Can be used more than once.
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -spiffeID string
    	SPIFFE ID of the X509-SVID
  -ttl duration
    	TTL of the X509-SVID
  -write string
    	Directory to write output to instead of stdout
`

	testKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOM2+vqaItpLD6z27
Z84JZjKUN33uWhKdlOVoBpplaJ6hRANCAAQXt5Kz8gRQiSxKhLDyzo7zT/CcGmZJ
+rW5Tfyoy0r7tlKjHxFbN6ogHCDBSrLD8NkqKiVAg2npdg4qC56OjWGz
-----END PRIVATE KEY-----
`

	testX509Authority = `-----BEGIN CERTIFICATE-----
MIIBjzCCATSgAwIBAgIBADAKBggqhkjOPQQDAjAeMQswCQYDVQQGEwJVUzEPMA0G
A1UEChMGU1BJRkZFMB4XDTIwMDgyMDE2MDMwNVoXDTIwMDgyMDE3MDMxNVowHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABOZa3K3iGa9IiECX51mnU62HdQO3GjwtZsn/x5IO/0a9YPHxAVP0N3lD
CHRKm7jVNiiBp8SppSHEd+r6ic8ij4GjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTSFjkGrSwV8L8u/2vdWA7a0lPb8jAfBgNV
HREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDAgNJADBGAiEA
mdUK1/3+csYw7oWsNuh9qxGOWOkLS6hjVAjJ/fAGd2oCIQCa7zJtmExCQLwbI0Ar
JMSEiviWUClVHE8G6t55aCHoBQ==
-----END CERTIFICATE-----
`
)

var (
	testKey, _ = pemutil.ParseSigner([]byte(testKeyPEM))
)

func TestMintSynopsis(t *testing.T) {
	cmd := NewMintCommand()
	assert.Equal(t, "Mints an X509-SVID", cmd.Synopsis())
}

func TestMintHelp(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd := newMintCommand(&common_cli.Env{
		Stdin:  new(bytes.Buffer),
		Stdout: stdout,
		Stderr: stderr,
	}, nil)
	assert.Equal(t, "flag: help requested", cmd.Help())
	assert.Empty(t, stdout.String())
	assert.Equal(t, expectedUsage, stderr.String())
}

func TestMintRun(t *testing.T) {
	dir := spiretest.TempDir(t)

	svidPath := filepath.Join(dir, "svid.pem")
	keyPath := filepath.Join(dir, "key.pem")
	bundlePath := filepath.Join(dir, "bundle.pem")

	notAfter := time.Now().Add(30 * time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, testKey.Public(), testKey)
	require.NoError(t, err)

	svidPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	server := new(fakeSVIDServer)
	spiretest.StartGRPCSocketServer(t, util.DefaultSocketPath, func(s *grpc.Server) {
		svidpb.RegisterSVIDServer(s, server)
		bundlepb.RegisterBundleServer(s, server)
	})

	alternativeSocket := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		svidpb.RegisterSVIDServer(s, server)
		bundlepb.RegisterBundleServer(s, server)
	})

	x509Authority, err := pemutil.ParseCertificate([]byte(testX509Authority))
	require.NoError(t, err)

	bundle := &types.Bundle{
		X509Authorities: []*types.X509Certificate{
			{
				Asn1: x509Authority.Raw,
			},
		},
	}

	testCases := []struct {
		name string

		// flags
		spiffeID   string
		ttl        time.Duration
		dnsNames   []string
		socketPath string
		write      string
		extraArgs  []string

		// results
		code   int
		stdin  string
		stderr string

		noRequestExpected bool
		resp              *svidpb.MintX509SVIDResponse

		bundle    *types.Bundle
		bundleErr error

		// generate key returned error
		generateErr error
	}{
		{
			name:              "missing spiffeID flag",
			code:              1,
			stderr:            "spiffeID must be specified\n",
			noRequestExpected: true,
		},
		{
			name:              "malformed spiffe ID",
			code:              1,
			spiffeID:          "malformed id",
			stderr:            "spiffeid: invalid scheme\n",
			noRequestExpected: true,
		},
		{
			name:              "invalid flag",
			code:              1,
			stderr:            fmt.Sprintf("flag provided but not defined: -bad\n%s\n", expectedUsage),
			extraArgs:         []string{"-bad", "flag"},
			noRequestExpected: true,
		},
		{
			name:              "generate key fails",
			spiffeID:          "spiffe://domain.test/workload",
			code:              1,
			generateErr:       errors.New("some error"),
			stderr:            "unable to generate key: some error\n",
			noRequestExpected: true,
		},
		{
			name:     "RPC fails",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "unable to mint SVID: rpc error: code = Unknown desc = response not configured in test\n",
		},
		{
			name:     "response missing SVID chain",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "server response missing SVID chain\n",
			resp: &svidpb.MintX509SVIDResponse{
				Svid: &types.X509SVID{},
			},
		},
		{
			name:     "get bundle fails",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "unable to get bundle: rpc error: code = Unknown desc = some error\n",
			resp: &svidpb.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
				},
			},
			bundleErr: errors.New("some error"),
		},
		{
			name:     "response missing root CAs",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "server response missing X509 Authorities\n",
			resp: &svidpb.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
				},
			},
			bundle: &types.Bundle{},
		},
		{
			name:     "success with defaults",
			spiffeID: "spiffe://domain.test/workload",
			code:     0,
			resp: &svidpb.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
					ExpiresAt: time.Now().Add(time.Minute).Unix(),
				},
			},
			bundle: bundle,
		},
		{
			name:       "success with ttl and dnsnames, written to directory, using alternate socket",
			spiffeID:   "spiffe://domain.test/workload",
			ttl:        time.Minute,
			socketPath: alternativeSocket,
			code:       0,
			write:      ".",
			resp: &svidpb.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
					ExpiresAt: notAfter.Unix(),
				},
			},
			bundle: bundle,
			stderr: fmt.Sprintf("X509-SVID lifetime was capped shorter than specified ttl; expires %q\n", notAfter.UTC().Format(time.RFC3339)),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			server.setMintX509SVIDResponse(testCase.resp)
			server.resetMintX509SVIDRequest()

			server.bundle = testCase.bundle
			server.bundleErr = testCase.bundleErr

			stdout := new(bytes.Buffer)
			stderr := new(bytes.Buffer)
			cmd := newMintCommand(&common_cli.Env{
				Stdin:   strings.NewReader(testCase.stdin),
				Stdout:  stdout,
				Stderr:  stderr,
				BaseDir: dir,
			}, func() (crypto.Signer, error) {
				if testCase.generateErr != nil {
					return nil, testCase.generateErr
				}
				return testKey, nil
			})

			args := []string{}
			if testCase.socketPath != "" {
				args = append(args, "-registrationUDSPath", testCase.socketPath)
			}
			if testCase.spiffeID != "" {
				args = append(args, "-spiffeID", testCase.spiffeID)
			}
			if testCase.ttl != 0 {
				args = append(args, "-ttl", fmt.Sprint(testCase.ttl))
			}
			if testCase.write != "" {
				args = append(args, "-write", testCase.write)
			}
			for _, dnsName := range testCase.dnsNames {
				args = append(args, "-dns", dnsName)
			}
			args = append(args, testCase.extraArgs...)

			code := cmd.Run(args)

			assert.Equal(t, testCase.code, code, "exit code does not match")
			assert.Equal(t, testCase.stderr, stderr.String(), "stderr does not match")

			req := server.lastMintX509SVIDRequest()
			if testCase.noRequestExpected {
				assert.Nil(t, req)
				return
			}

			if assert.NotNil(t, req) {
				assert.NotEmpty(t, req.Csr)
				csr, err := x509.ParseCertificateRequest(req.Csr)
				require.NoError(t, err)

				id := spiffeid.RequireFromString(testCase.spiffeID)
				require.Equal(t, id.URL(), csr.URIs[0])

				require.Equal(t, testCase.dnsNames, csr.DNSNames)
				assert.Equal(t, int32(testCase.ttl/time.Second), req.Ttl)
			}

			// assert output file contents
			if code == 0 {
				if testCase.write != "" {
					assert.Equal(t, fmt.Sprintf(`X509-SVID written to %s
Private key written to %s
Root CAs written to %s
`, svidPath, keyPath, bundlePath),
						stdout.String(), "stdout does not write output paths")
					assertFileData(t, filepath.Join(dir, testCase.write, "svid.pem"), svidPEM)
					assertFileData(t, filepath.Join(dir, testCase.write, "key.pem"), testKeyPEM)
					assertFileData(t, filepath.Join(dir, testCase.write, "bundle.pem"), testX509Authority)
				} else {
					assert.Equal(t, fmt.Sprintf(`X509-SVID:
%s
Private key:
%s
Root CAs:
%s
`, svidPEM, testKeyPEM, testX509Authority), stdout.String(), "stdout does not write out PEM")
				}
			}
		})
	}
}

type fakeSVIDServer struct {
	svidpb.SVIDServer
	bundlepb.BundleServer

	mu   sync.Mutex
	req  *svidpb.MintX509SVIDRequest
	resp *svidpb.MintX509SVIDResponse

	bundle    *types.Bundle
	bundleErr error
}

func (f *fakeSVIDServer) resetMintX509SVIDRequest() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.req = nil
}

func (f *fakeSVIDServer) lastMintX509SVIDRequest() *svidpb.MintX509SVIDRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.req
}

func (f *fakeSVIDServer) setMintX509SVIDResponse(resp *svidpb.MintX509SVIDResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp = resp
}

func (f *fakeSVIDServer) MintX509SVID(ctx context.Context, req *svidpb.MintX509SVIDRequest) (*svidpb.MintX509SVIDResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.req = req
	if f.resp == nil {
		return nil, errors.New("response not configured in test")
	}
	return f.resp, nil
}

func (f *fakeSVIDServer) GetBundle(ctx context.Context, req *bundlepb.GetBundleRequest) (*types.Bundle, error) {
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}

	return f.bundle, nil
}

func assertFileData(t *testing.T, path string, expectedData string) {
	b, err := ioutil.ReadFile(path)
	if assert.NoError(t, err) {
		assert.Equal(t, expectedData, string(b))
	}
}
