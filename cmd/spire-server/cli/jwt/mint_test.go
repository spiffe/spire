package jwt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
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
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	testKey, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`))
)

const (
	expectedUsage = `Usage of jwt mint:
  -audience value
    	Audience claim that will be included in the SVID. Can be used more than once.
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -spiffeID string
    	SPIFFE ID of the JWT-SVID
  -ttl duration
    	TTL of the JWT-SVID
  -write string
    	File to write token to instead of stdout
`
)

func TestMintSynopsis(t *testing.T) {
	cmd := NewMintCommand()
	assert.Equal(t, "Mints a JWT-SVID", cmd.Synopsis())
}

func TestMintHelp(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd := newMintCommand(&common_cli.Env{
		Stdin:  new(bytes.Buffer),
		Stdout: stdout,
		Stderr: stderr,
	})
	assert.Empty(t, cmd.Help())
	assert.Empty(t, stdout.String())
	assert.Equal(t, expectedUsage, stderr.String())
}

func TestMintRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	svidPath := filepath.Join(dir, "token")

	api := new(FakeRegistrationAPI)

	defaultServerDone := spiretest.StartRegistrationAPIOnSocket(t, filepath.Join(dir, util.DefaultSocketPath), api)
	defer defaultServerDone()

	otherServerDone := spiretest.StartRegistrationAPIOnSocket(t, filepath.Join(dir, "other.sock"), api)
	defer otherServerDone()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       testKey,
	}, nil)
	require.NoError(t, err)

	expiry := time.Now().Add(30 * time.Second)
	builder := jwt.Signed(signer).Claims(jwt.Claims{
		Expiry: jwt.NewNumericDate(expiry),
	})
	token, err := builder.CompactSerialize()
	require.NoError(t, err)

	testCases := []struct {
		name string

		// flags
		spiffeID   string
		ttl        time.Duration
		audience   []string
		socketPath string
		write      string
		extraArgs  []string

		// results
		code   int
		stdin  string
		stderr string

		noRequestExpected bool
		resp              *registration.MintJWTSVIDResponse
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
			audience: []string{"AUDIENCE"},
			code:     1,
			stderr:   "error: unable to mint SVID: rpc error: code = Unknown desc = response not configured in test\n",
		},
		{
			name:     "response missing token",
			spiffeID: "spiffe://domain.test/workload",
			audience: []string{"AUDIENCE"},
			code:     1,
			stderr:   "error: server response missing token\n",
			resp:     &registration.MintJWTSVIDResponse{},
		},
		{
			name:     "success with defaults",
			spiffeID: "spiffe://domain.test/workload",
			audience: []string{"AUDIENCE"},
			code:     0,
			resp: &registration.MintJWTSVIDResponse{
				Token: token,
			},
		},
		{
			name:       "success with ttl and extra audience, output to file, using alternate socket",
			spiffeID:   "spiffe://domain.test/workload",
			ttl:        time.Minute,
			audience:   []string{"AUDIENCE1", "AUDIENCE2"},
			socketPath: "other.sock",
			code:       0,
			write:      "token",
			resp: &registration.MintJWTSVIDResponse{
				Token: token,
			},
			stderr: fmt.Sprintf("JWT-SVID lifetime was capped shorter than specified ttl; expires %q\n", expiry.UTC().Format(time.RFC3339)),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			api.SetMintJWTSVIDResponse(testCase.resp)

			stdout := new(bytes.Buffer)
			stderr := new(bytes.Buffer)
			cmd := newMintCommand(&common_cli.Env{
				Stdin:   strings.NewReader(testCase.stdin),
				Stdout:  stdout,
				Stderr:  stderr,
				BaseDir: dir,
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
			for _, audience := range testCase.audience {
				args = append(args, "-audience", audience)
			}
			args = append(args, testCase.extraArgs...)

			code := cmd.Run(args)

			assert.Equal(t, testCase.code, code, "exit code does not match")
			assert.Equal(t, testCase.stderr, stderr.String(), "stderr does not match")

			req := api.LastMintJWTSVIDRequest()
			if testCase.noRequestExpected {
				assert.Nil(t, req)
				return
			}

			if assert.NotNil(t, req) {
				assert.Equal(t, testCase.spiffeID, req.SpiffeId)
				assert.Equal(t, int32(testCase.ttl/time.Second), req.Ttl)
				assert.Equal(t, testCase.audience, req.Audience)
			}

			// assert output file contents
			if code == 0 {
				if testCase.write != "" {
					assert.Equal(t, fmt.Sprintf("JWT-SVID written to %s\n", svidPath),
						stdout.String(), "stdout does not write output path")
					assertFileData(t, filepath.Join(dir, testCase.write), testCase.resp.Token)
				} else {
					assert.Equal(t, stdout.String(), testCase.resp.Token+"\n")
				}
			}
		})
	}
}

type FakeRegistrationAPI struct {
	registration.RegistrationServer

	mu   sync.Mutex
	req  *registration.MintJWTSVIDRequest
	resp *registration.MintJWTSVIDResponse
}

func (r *FakeRegistrationAPI) LastMintJWTSVIDRequest() *registration.MintJWTSVIDRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.req
}

func (r *FakeRegistrationAPI) SetMintJWTSVIDResponse(resp *registration.MintJWTSVIDResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resp = resp
}

func (r *FakeRegistrationAPI) MintJWTSVID(ctx context.Context, req *registration.MintJWTSVIDRequest) (*registration.MintJWTSVIDResponse, error) {
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
