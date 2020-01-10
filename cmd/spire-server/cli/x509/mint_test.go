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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	testBundlePEM = `-----BEGIN CERTIFICATE-----
AQ==
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
	assert.Empty(t, cmd.Help())
	assert.Empty(t, stdout.String())
	assert.Equal(t, expectedUsage, stderr.String())
}

func TestMintRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

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

	api := new(FakeRegistrationAPI)

	defaultServerDone := spiretest.StartRegistrationAPIOnSocket(t, filepath.Join(dir, util.DefaultSocketPath), api)
	defer defaultServerDone()

	otherServerDone := spiretest.StartRegistrationAPIOnSocket(t, filepath.Join(dir, "other.sock"), api)
	defer otherServerDone()

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
		resp              *registration.MintX509SVIDResponse
	}{
		{
			name:              "missing spiffeID flag",
			code:              1,
			stderr:            "error: spiffeID must be specified\n",
			noRequestExpected: true,
		},
		{
			name:              "invalid flag",
			code:              1,
			stderr:            "flag provided but not defined: -bad\n" + expectedUsage,
			extraArgs:         []string{"-bad", "flag"},
			noRequestExpected: true,
		},
		{
			name:     "RPC fails",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "error: unable to mint SVID: rpc error: code = Unknown desc = response not configured in test\n",
		},
		{
			name:     "response missing SVID chain",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "error: server response missing SVID chain\n",
			resp: &registration.MintX509SVIDResponse{
				RootCas: [][]byte{{0x01}},
			},
		},
		{
			name:     "response missing root CAs",
			spiffeID: "spiffe://domain.test/workload",
			code:     1,
			stderr:   "error: server response missing root CAs\n",
			resp: &registration.MintX509SVIDResponse{
				SvidChain: [][]byte{certDER},
			},
		},
		{
			name:     "success with defaults",
			spiffeID: "spiffe://domain.test/workload",
			code:     0,
			resp: &registration.MintX509SVIDResponse{
				SvidChain: [][]byte{certDER},
				RootCas:   [][]byte{{0x01}},
			},
		},
		{
			name:       "success with ttl and dnsnames, written to directory, using alternate socket",
			spiffeID:   "spiffe://domain.test/workload",
			ttl:        time.Minute,
			socketPath: "other.sock",
			code:       0,
			write:      ".",
			resp: &registration.MintX509SVIDResponse{
				SvidChain: [][]byte{certDER},
				RootCas:   [][]byte{{0x01}},
			},
			stderr: fmt.Sprintf("X509-SVID lifetime was capped shorter than specified ttl; expires %q\n", notAfter.UTC().Format(time.RFC3339)),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			api.SetMintX509SVIDResponse(testCase.resp)

			stdout := new(bytes.Buffer)
			stderr := new(bytes.Buffer)
			cmd := newMintCommand(&common_cli.Env{
				Stdin:   strings.NewReader(testCase.stdin),
				Stdout:  stdout,
				Stderr:  stderr,
				BaseDir: dir,
			}, func() (crypto.Signer, error) {
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

			req := api.LastMintX509SVIDRequest()
			if testCase.noRequestExpected {
				assert.Nil(t, req)
				return
			}

			if assert.NotNil(t, req) {
				assert.NotEmpty(t, req.Csr)
				assert.Equal(t, testCase.spiffeID, req.SpiffeId)
				assert.Equal(t, int32(testCase.ttl/time.Second), req.Ttl)
				assert.Equal(t, testCase.dnsNames, req.DnsNames)
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
					assertFileData(t, filepath.Join(dir, testCase.write, "bundle.pem"), testBundlePEM)
				} else {
					assert.Equal(t, fmt.Sprintf(`X509-SVID:
%s
Private key:
%s
Root CAs:
%s
`, svidPEM, testKeyPEM, testBundlePEM), stdout.String(), "stdout does not write out PEM")
				}
			}
		})
	}
}

type FakeRegistrationAPI struct {
	registration.RegistrationServer

	mu   sync.Mutex
	req  *registration.MintX509SVIDRequest
	resp *registration.MintX509SVIDResponse
}

func (r *FakeRegistrationAPI) LastMintX509SVIDRequest() *registration.MintX509SVIDRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.req
}

func (r *FakeRegistrationAPI) SetMintX509SVIDResponse(resp *registration.MintX509SVIDResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resp = resp
}

func (r *FakeRegistrationAPI) MintX509SVID(ctx context.Context, req *registration.MintX509SVIDRequest) (*registration.MintX509SVIDResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.req = req
	if r.resp == nil {
		return nil, errors.New("response not configured in test")
	}
	return r.resp, nil
}

func assertFileData(t *testing.T, path string, expectedData string) {
	b, err := ioutil.ReadFile(path)
	if assert.NoError(t, err) {
		assert.Equal(t, expectedData, string(b))
	}
}
