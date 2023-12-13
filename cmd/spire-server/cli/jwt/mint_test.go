package jwt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
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
	testKey, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`))
	availableFormats = []string{"pretty", "json"}
	expectedUsage    = `Usage of jwt mint:
  -audience value
    	Audience claim that will be included in the SVID. Can be used more than once.` + common.AddrOutputUsage +
		`  -spiffeID string
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
	assert.Equal(t, "flag: help requested", cmd.Help())
	assert.Empty(t, stdout.String())
	assert.Equal(t, expectedUsage, stderr.String())
}

func TestMintRun(t *testing.T) {
	dir := spiretest.TempDir(t)
	svidPath := filepath.Join(dir, "token")
	server := new(fakeSVIDServer)
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		svidv1.RegisterSVIDServer(s, server)
	})

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

	// Create expired token
	expiredAt := time.Now().Add(-30 * time.Second)
	builder = jwt.Signed(signer).Claims(jwt.Claims{
		Expiry: jwt.NewNumericDate(expiredAt),
	})
	expiredToken, err := builder.CompactSerialize()
	require.NoError(t, err)

	testCases := []struct {
		name string

		// flags
		spiffeID  string
		expectID  *types.SPIFFEID
		ttl       time.Duration
		audience  []string
		write     string
		extraArgs []string

		// results
		code      int
		stdin     string
		expStderr string

		noRequestExpected bool
		expStdoutPretty   string
		expStdoutJSON     string
		resp              *svidv1.MintJWTSVIDResponse
	}{
		{
			name:              "missing spiffeID flag",
			code:              1,
			expStderr:         "Error: spiffeID must be specified\n",
			noRequestExpected: true,
		},
		{
			name:              "invalid flag",
			code:              1,
			expStderr:         fmt.Sprintf("flag provided but not defined: -bad\n%s", expectedUsage),
			extraArgs:         []string{"-bad", "flag"},
			noRequestExpected: true,
		},
		{
			name:     "RPC fails",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience:  []string{"AUDIENCE"},
			code:      1,
			expStderr: "Error: unable to mint SVID: rpc error: code = Unknown desc = response not configured in test\n",
		},
		{
			name:     "response missing token",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience:  []string{"AUDIENCE"},
			code:      1,
			expStderr: "Error: server response missing token\n",
			resp:      &svidv1.MintJWTSVIDResponse{Svid: &types.JWTSVID{}},
		},
		{
			name:     "missing audience",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			code:              1,
			expStderr:         "Error: at least one audience must be specified\n",
			audience:          []string{},
			noRequestExpected: true,
		},
		{
			name:     "malformed spiffeID",
			spiffeID: "domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			code:              1,
			expStderr:         "Error: scheme is missing or invalid\n",
			audience:          []string{"AUDIENCE"},
			noRequestExpected: true,
		},
		{
			name:     "success with defaults",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience: []string{"AUDIENCE"},
			code:     0,
			resp: &svidv1.MintJWTSVIDResponse{
				Svid: &types.JWTSVID{
					Token: token,
					Id: &types.SPIFFEID{
						TrustDomain: "domain.test",
						Path:        "/workload",
					},
					ExpiresAt: 1628600000,
					IssuedAt:  1628500000,
				},
			},
			expStdoutPretty: token + "\n",
			expStdoutJSON: fmt.Sprintf(`{
  "svid": {
    "token": "%s",
    "id": {
	  "trust_domain": "domain.test",
	  "path": "/workload"
	},
    "expires_at": "1628600000",
    "hint": "",
    "issued_at": "1628500000"
  }
}`, token)},

		{
			name:     "write on invalid path",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience: []string{"AUDIENCE"},
			code:     1,
			resp: &svidv1.MintJWTSVIDResponse{
				Svid: &types.JWTSVID{
					Token: token,
				},
			},
			write:           "/",
			expStdoutPretty: token + "\n",
			expStdoutJSON:   `{}`,
			expStderr:       "Error: unable to write token",
		},
		{
			name:     "malformed token",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience: []string{"AUDIENCE"},
			code:     0,
			resp: &svidv1.MintJWTSVIDResponse{
				Svid: &types.JWTSVID{
					Token: "malformed token",
				},
			},
			expStdoutPretty: "malformed token\n",
			expStdoutJSON: `{
  "svid": {
    "token": "malformed token",
    "expires_at": "0",
    "hint": "",
    "issued_at": "0"
  }
}`,
			expStderr: "Unable to determine JWT-SVID lifetime: go-jose/go-jose: compact JWS format must have three parts\n",
		},
		{
			name:     "expired token",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			audience: []string{"AUDIENCE"},
			code:     0,
			resp: &svidv1.MintJWTSVIDResponse{
				Svid: &types.JWTSVID{
					Token: expiredToken,
					Id: &types.SPIFFEID{
						TrustDomain: "domain.test",
						Path:        "/workload",
					},
					ExpiresAt: 1628500000,
					IssuedAt:  1628600000,
				},
			},
			expStdoutPretty: expiredToken + "\n",
			expStdoutJSON: fmt.Sprintf(`{
  "svid": {
    "token": "%s",
    "id": {
	  "trust_domain": "domain.test",
	  "path": "/workload"
	},
    "expires_at": "1628500000",
    "hint": "",
    "issued_at": "1628600000"
  }
}`, expiredToken),
			expStderr: fmt.Sprintf("JWT-SVID lifetime was capped shorter than specified ttl; expires %q\n", expiredAt.UTC().Format(time.RFC3339)),
		},
		{
			name:     "success with ttl and extra audience, output to file",
			spiffeID: "spiffe://domain.test/workload",
			expectID: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/workload",
			},
			ttl:      time.Minute,
			audience: []string{"AUDIENCE1", "AUDIENCE2"},
			code:     0,
			write:    "token",
			resp: &svidv1.MintJWTSVIDResponse{
				Svid: &types.JWTSVID{
					Token: token,
				},
			},
			expStdoutPretty: token + "\n",
			expStdoutJSON:   `{}`,
			expStderr:       fmt.Sprintf("JWT-SVID lifetime was capped shorter than specified ttl; expires %q\n", expiry.UTC().Format(time.RFC3339)),
		},
	}

	for _, testCase := range testCases {
		tt := testCase
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				server.setMintJWTSVIDResponse(tt.resp)
				server.resetMintJWTSVIDRequest()

				stdout := new(bytes.Buffer)
				stderr := new(bytes.Buffer)
				cmd := newMintCommand(&common_cli.Env{
					Stdin:   strings.NewReader(tt.stdin),
					Stdout:  stdout,
					Stderr:  stderr,
					BaseDir: dir,
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
				for _, audience := range tt.audience {
					args = append(args, "-audience", audience)
				}
				args = append(args, tt.extraArgs...)
				args = append(args, "-output", format)

				code := cmd.Run(args)

				assert.Equal(t, tt.code, code, "exit code does not match")
				assert.Contains(t, stderr.String(), tt.expStderr, "stderr does not match")

				req := server.lastMintJWTSVIDRequest()
				if tt.noRequestExpected {
					assert.Nil(t, req)
					return
				}

				if assert.NotNil(t, req) {
					assert.Equal(t, tt.expectID, req.Id)
					assert.Equal(t, int32(tt.ttl/time.Second), req.Ttl)
					assert.Equal(t, tt.audience, req.Audience)
				}

				// assert output file contents
				if code == 0 {
					if tt.write != "" {
						assert.Equal(t, fmt.Sprintf("JWT-SVID written to %s\n", svidPath),
							stdout.String(), "stdout does not write output path")
						assertFileData(t, filepath.Join(dir, tt.write), tt.resp.Svid.Token)
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

	mu   sync.Mutex
	req  *svidv1.MintJWTSVIDRequest
	resp *svidv1.MintJWTSVIDResponse
}

func (f *fakeSVIDServer) resetMintJWTSVIDRequest() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.req = nil
}

func (f *fakeSVIDServer) lastMintJWTSVIDRequest() *svidv1.MintJWTSVIDRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.req
}

func (f *fakeSVIDServer) setMintJWTSVIDResponse(resp *svidv1.MintJWTSVIDResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp = resp
}

func (f *fakeSVIDServer) MintJWTSVID(_ context.Context, req *svidv1.MintJWTSVIDRequest) (*svidv1.MintJWTSVIDResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.req = req
	if f.resp == nil {
		return nil, errors.New("response not configured in test")
	}
	return f.resp, nil
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
