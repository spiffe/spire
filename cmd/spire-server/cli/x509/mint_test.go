package x509

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	expectedUsage = `Usage of x509 mint:
  -dns value
    	DNS name that will be included in SVID. Can be used more than once.` + common.AddrOutputUsage +
		`  -spiffeID string
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
	testKey, _       = pemutil.ParseSigner([]byte(testKeyPEM))
	availableFormats = []string{"pretty", "json"}
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
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		svidv1.RegisterSVIDServer(s, server)
		bundlev1.RegisterBundleServer(s, server)
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
	block, _ := pem.Decode([]byte(testKeyPEM))
	privateKeyBase64 := base64.StdEncoding.EncodeToString(block.Bytes)

	var certDerPem, rootCaPem bytes.Buffer
	err = pem.Encode(&certDerPem, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)
	err = pem.Encode(&rootCaPem, &pem.Block{Type: "CERTIFICATE", Bytes: x509Authority.Raw})
	require.NoError(t, err)

	testCases := []struct {
		name string

		// flags
		spiffeID  string
		ttl       time.Duration
		dnsNames  []string
		write     string
		extraArgs []string

		// results
		code   int
		stdin  string
		stderr string

		noRequestExpected bool
		resp              *svidv1.MintX509SVIDResponse

		bundle    *types.Bundle
		bundleErr error

		// generate key returned error
		generateErr     error
		expStdoutPretty string
		expStdoutJSON   string
	}{
		{
			name:              "missing spiffeID flag",
			code:              1,
			stderr:            "Error: spiffeID must be specified\n",
			noRequestExpected: true,
		},
		{
			name:              "malformed spiffe ID",
			code:              1,
			spiffeID:          "malformed id",
			stderr:            "Error: scheme is missing or invalid\n",
			noRequestExpected: true,
		},
		{
			name:              "invalid flag",
			code:              1,
			stderr:            fmt.Sprintf("flag provided but not defined: -bad\n%s", expectedUsage),
			extraArgs:         []string{"-bad", "flag"},
			noRequestExpected: true,
		},
		{
			name:              "generate key fails",
			spiffeID:          "spiffe://domain.test/workload",
			code:              1,
			generateErr:       errors.New("some error"),
			stderr:            "Error: unable to generate key: some error\n",
			noRequestExpected: true,
		},
		{
			name:     "RPC fails",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "Error: unable to mint SVID: rpc error: code = Unknown desc = response not configured in test\n",
		},
		{
			name:     "response missing SVID chain",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "Error: server response missing SVID chain\n",
			resp: &svidv1.MintX509SVIDResponse{
				Svid: &types.X509SVID{},
			},
		},
		{
			name:     "get bundle fails",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "Error: unable to get bundle: rpc error: code = Unknown desc = some error\n",
			resp: &svidv1.MintX509SVIDResponse{
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
			stderr:   "Error: server response missing X509 Authorities\n",
			resp: &svidv1.MintX509SVIDResponse{
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
			resp: &svidv1.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
					ExpiresAt: time.Now().Add(time.Minute).Unix(),
				},
			},
			bundle: bundle,
			expStdoutPretty: fmt.Sprintf(`X509-SVID:
%s
Private key:
%s
Root CAs:
%s
`, certDerPem.String(), testKeyPEM, rootCaPem.String()),
			expStdoutJSON: fmt.Sprintf(`[
  {
    "x509_svid": [
      "%s"
    ],
    "private_key": "%s",
    "root_cas": [
      "%s"
    ]
  }
]`, base64.StdEncoding.EncodeToString(certDER), privateKeyBase64, base64.StdEncoding.EncodeToString(x509Authority.Raw)),
		},
		{
			name:     "success with ttl and dnsnames, written to directory",
			spiffeID: "spiffe://domain.test/workload",
			ttl:      time.Minute,
			code:     0,
			write:    ".",
			resp: &svidv1.MintX509SVIDResponse{
				Svid: &types.X509SVID{
					CertChain: [][]byte{certDER},
					ExpiresAt: notAfter.Unix(),
				},
			},
			bundle:          bundle,
			expStdoutPretty: "",
			expStdoutJSON:   `{}`,
			stderr:          fmt.Sprintf("X509-SVID lifetime was capped shorter than specified ttl; expires %q\n", notAfter.UTC().Format(time.RFC3339)),
		},
	}

	for _, tt := range testCases {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				server.setMintX509SVIDResponse(tt.resp)
				server.resetMintX509SVIDRequest()

				server.bundle = tt.bundle
				server.bundleErr = tt.bundleErr

				stdout := new(bytes.Buffer)
				stderr := new(bytes.Buffer)
				cmd := newMintCommand(&common_cli.Env{
					Stdin:   strings.NewReader(tt.stdin),
					Stdout:  stdout,
					Stderr:  stderr,
					BaseDir: dir,
				}, func() (crypto.Signer, error) {
					if tt.generateErr != nil {
						return nil, tt.generateErr
					}
					return testKey, nil
				})

				args := []string{common.AddrArg, common.GetAddr(addr)}
				if tt.spiffeID != "" {
					args = append(args, "-spiffeID", tt.spiffeID)
				}
				if tt.ttl != 0 {
					args = append(args, "-ttl", fmt.Sprint(tt.ttl))
				}
				if tt.write != "" {
					args = append(args, "-write", tt.write)
				}
				for _, dnsName := range tt.dnsNames {
					args = append(args, "-dns", dnsName)
				}
				args = append(args, tt.extraArgs...)
				args = append(args, "-output", format)

				code := cmd.Run(args)

				assert.Equal(t, tt.code, code, "exit code does not match")
				assert.Equal(t, tt.stderr, stderr.String(), "stderr does not match")

				req := server.lastMintX509SVIDRequest()
				if tt.noRequestExpected {
					assert.Nil(t, req)
					return
				}

				if assert.NotNil(t, req) {
					assert.NotEmpty(t, req.Csr)
					csr, err := x509.ParseCertificateRequest(req.Csr)
					require.NoError(t, err)

					id := spiffeid.RequireFromString(tt.spiffeID)
					require.Equal(t, id.URL(), csr.URIs[0])

					require.Equal(t, tt.dnsNames, csr.DNSNames)
					assert.Equal(t, int32(tt.ttl/time.Second), req.Ttl)
				}

				// assert output file contents
				if code == 0 {
					if tt.write != "" {
						assert.Equal(t, fmt.Sprintf(`X509-SVID written to %s
Private key written to %s
Root CAs written to %s
`, svidPath, keyPath, bundlePath),
							stdout.String(), "stdout does not write output paths")
						assertFileData(t, filepath.Join(dir, tt.write, "svid.pem"), svidPEM)
						assertFileData(t, filepath.Join(dir, tt.write, "key.pem"), testKeyPEM)
						assertFileData(t, filepath.Join(dir, tt.write, "bundle.pem"), testX509Authority)
					} else {
						requireOutputBasedOnFormat(t, format, stdout.String(), tt.expStdoutPretty, tt.expStdoutJSON)
					}
				}
			})
		}
	}
}

type fakeSVIDServer struct {
	svidv1.SVIDServer
	bundlev1.BundleServer

	mu   sync.Mutex
	req  *svidv1.MintX509SVIDRequest
	resp *svidv1.MintX509SVIDResponse

	bundle    *types.Bundle
	bundleErr error
}

func (f *fakeSVIDServer) resetMintX509SVIDRequest() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.req = nil
}

func (f *fakeSVIDServer) lastMintX509SVIDRequest() *svidv1.MintX509SVIDRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.req
}

func (f *fakeSVIDServer) setMintX509SVIDResponse(resp *svidv1.MintX509SVIDResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp = resp
}

func (f *fakeSVIDServer) MintX509SVID(ctx context.Context, req *svidv1.MintX509SVIDRequest) (*svidv1.MintX509SVIDResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.req = req
	if f.resp == nil {
		return nil, errors.New("response not configured in test")
	}
	return f.resp, nil
}

func (f *fakeSVIDServer) GetBundle(ctx context.Context, req *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}

	return f.bundle, nil
}

func assertFileData(t *testing.T, path string, expectedData string) {
	b, err := os.ReadFile(path)
	if assert.NoError(t, err) {
		assert.Equal(t, expectedData, string(b))
	}
}

func requireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
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
