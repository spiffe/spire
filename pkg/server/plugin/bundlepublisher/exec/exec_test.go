package exec

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var tmpFile *os.File

func stubCommand(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--"}
	tmpFile, err := os.CreateTemp("", "bundle-*.spiffe")
	if err != nil {
		return nil
	}
	tmpFile.Close()
	cs = append(cs, tmpFile.Name())
	if command == "false" {
		cs = append(cs, "fail")
	} else {
		cs = append(cs, "succeed")
	}
	// Push trust bundle to user configured process
	// We use gosec -- the annotation below will disable a security check that users didn't specify the command
	// Its their command.
	/* #nosec G204 */
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"HELPER_PROCESS=1"}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("HELPER_PROCESS") != "1" {
		return
	}
	if os.Args[4] == "fail" {
		os.Exit(1)
	}
	file, err := os.Create(os.Args[3])
	if err != nil {
		os.Exit(1)
	}
	_, err = io.Copy(file, os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest *configv1.ConfigureRequest
		newClientErr     error
		expectCode       codes.Code
		expectMsg        string
		config           *Config
	}{
		{
			name: "success",
			config: &Config{
				Cmd:    "cat",
				Args:   []string{},
				Format: "spiffe",
			},
		},
		{
			name: "no cmd",
			config: &Config{
				Format: "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to decode configuration: At -",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			p := newPlugin()

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration.
			tt.config.bundleFormat, err = bundleformat.FromString(tt.config.Format)
			require.NoError(t, err)
			require.Equal(t, tt.config, p.config)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	execCommandContext = stubCommand
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		newClientErr error
		expectCode   codes.Code
		expectMsg    string
		config       *Config
		bundle       *types.Bundle
		putObjectErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				Cmd:    "cat",
				Args:   []string{},
				Format: "spiffe",
			},
		},
		{
			name:   "multiple times",
			bundle: testBundle,
			config: &Config{
				Cmd:    "cat",
				Args:   []string{},
				Format: "spiffe",
			},
		},
		{
			name:   "fail",
			bundle: testBundle,
			config: &Config{
				Cmd:    "false",
				Args:   []string{},
				Format: "spiffe",
			},
			putObjectErr: errors.New("some error"),
			expectCode:   codes.Internal,
			expectMsg:    "failed to run: exit status 1",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				Cmd:    "cat",
				Args:   []string{},
				Format: "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}
			p := newPlugin()

			if tt.config != nil {
				plugintest.Load(t, builtin(p), nil, options...)
				require.NoError(t, err)
			}
			tmpFile = nil

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			if tmpFile != nil {
				trustDomain, err := spiffeid.TrustDomainFromString("example.org")
				require.NoError(t, err)
				bundle, err := spiffebundle.Load(trustDomain, tmpFile.Name())
				require.NoError(t, err)
				require.True(t, len(bundle.X509Authorities()) > 0, "The exec failed to get data")
				os.Remove(tmpFile.Name())
				tmpFile = nil
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
