package disk

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	x509CertPem = `-----BEGIN CERTIFICATE-----
MIICcDCCAdKgAwIBAgIBAjAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UEChMGU1BJRkZFMB4XDTE4MDIxMDAwMzY1NVoXDTE4MDIxMDAxMzY1NlowHTEL
MAkGA1UEBhMCVVMxDjAMBgNVBAoTBVNQSVJFMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQBfav2iunAwzozmwg5lq30ltm/X3XeBgxhbsWu4Rv+I5B22urvR0jxGQM7
TsquuQ/wpmJQgTgV9jnK/5fvl4GvhS8A+K2UXv6L3IlrHIcMG3VoQ+BeKo44Hwgu
keu5GMUKAiEF33acNWUHp7U+Swxdxw+CwR9bNnIf0ZTfxlqSBaJGVIujgb4wgbsw
DgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPhG423HoTvTKNXTAi9TKsaQwpzPMFsG
A1UdEQRUMFKGUHNwaWZmZTovL2V4YW1wbGUub3JnL3NwaXJlL2FnZW50L2pvaW5f
dG9rZW4vMmNmMzUzOGMtNGY5Yy00NmMwLWE1MjYtMWNhNjc5YTkyNDkyMAoGCCqG
SM49BAMEA4GLADCBhwJBLM2CaOSw8kzSBJUyAvg32PM1PhzsVEsGIzWS7b+hgKkJ
NlnJx6MZ82eamOCsCdTVrXUV5cxO8kt2yTmYxF+ucu0CQgGVmL65pzg2E4YfCES/
4th19FFMRiOTtNpI5j2/qLTptnanJ/rpqE0qsgA2AiSsnbnnW6B7Oa+oi7QDMOLw
l6+bdA==
-----END CERTIFICATE-----
`
	x509KeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`
	x509BundlePem = `-----BEGIN CERTIFICATE-----
MIICOTCCAZqgAwIBAgIBATAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UECgwGU1BJRkZFMB4XDTE4MDIxMDAwMzQ0NVoXDTE4MDIxMDAxMzQ1NVowHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTCBmzAQBgcqhkjOPQIBBgUrgQQA
IwOBhgAEAZ6nXrNctKHNjZT7ZkP7xwfpMfvc/DAHc39GdT3qi8mmowY0/XuFQmlJ
cXXwv8ZlOSoGvtuLAEx1lvHNZwv4BuuPALILcIW5tyC8pjcbfqs8PMQYwiC+oFKH
BTxXzolpLeHuFLAD9ccfwWhkT1z/t4pvLkP4FCkkBosG9PVg5JQVJuZJo4GFMIGC
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT4RuNt
x6E70yjV0wIvUyrGkMKczzAfBgNVHSMEGDAWgBRGyozl9Mjue0Y3w4c2Q+3u+wVk
CjAfBgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDBAOB
jAAwgYgCQgHOtx4sNCioAQnpEx3J/A9M6Lutth/ND/h8D+7luqEkd4tMrBQgnMj4
E0xLGUNtoFNRIrEUlgwksWvKZ3BksIIOMwJCAc8VPA/QYrlJDeQ58FKyQyrOIlPk
Q0qBJEOkL6FrAngY5218TCNUS30YS5HjI2lfyyjB+cSVFXX8Szu019dDBMhV
-----END CERTIFICATE-----
`
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name            string
		customConfig    string
		expectConfig    *configuration
		expectCode      codes.Code
		expectMsgPrefix string
	}{
		{
			name:            "no directory provided",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "a directory must be configured",
			expectConfig:    &configuration{},
		},
		{
			name:         "valild config",
			expectConfig: &configuration{Directory: t.TempDir()},
			expectCode:   codes.OK,
		},
		{
			name:            "malformed configuration",
			customConfig:    "{ not a config }",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration: ",
			expectConfig:    nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
			}

			if tt.customConfig != "" {
				options = append(options, plugintest.Configure(tt.customConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(configuration{
					Directory: tt.expectConfig.Directory,
				}))
			}

			p := New()
			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)

			require.Equal(t, tt.expectConfig, p.config)
		})
	}
}

func TestPutX509SVID(t *testing.T) {
	x509Cert, err := pemutil.ParseCertificate([]byte(x509CertPem))
	require.NoError(t, err)

	x509Key, err := pemutil.ParseECPrivateKey([]byte(x509KeyPem))
	require.NoError(t, err)

	x509Bundle, err := pemutil.ParseCertificate([]byte(x509BundlePem))
	require.NoError(t, err)

	for _, tt := range []struct {
		name string

		req           *svidstore.X509SVID
		expectCode    codes.Code
		expectMsg     string
		certChainFile string
		keyFile       string
		bundleFile    string
	}{
		{
			name:          "Put X509-SVID (successful)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
		},
		{
			name:          "Put X509-SVID (successful)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
		},
		{
			name:          "Put X509-SVID (non existent directory)",
			certChainFile: "new/directory/tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
		},
		{
			name:          "Put X509-SVID (no key file name)",
			certChainFile: "tls.crt",
			bundleFile:    "ca.crt",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): rpc error: code = InvalidArgument desc = keyfile must be specified",
		},
		{
			name:          "Put X509-SVID (no bundle file name)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): rpc error: code = InvalidArgument desc = bundlefile must be specified",
		},
		{
			name:          "Put X509-SVID (invalid cert file name)",
			certChainFile: "../../tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): rpc error: code = InvalidArgument desc = invalid certchainfile",
		},
		{
			name:          "Put X509-SVID (invalid key file name)",
			certChainFile: "tls.crt",
			keyFile:       "../../tls.key",
			bundleFile:    "ca.crt",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): rpc error: code = InvalidArgument desc = invalid keyfile",
		},
		{
			name:          "Put X509-SVID (invalid bundle file name)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "../../ca.crt",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): rpc error: code = InvalidArgument desc = invalid bundlefile",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			p := New()
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&configuration{Directory: t.TempDir()}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			err = ss.PutX509SVID(ctx, &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/svid"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{x509Bundle},
					ExpiresAt:  time.Now(),
				},
				Metadata: buildMetadata(tt.certChainFile, tt.keyFile, tt.bundleFile)})

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}
			require.NoError(t, err)

			certChain, err := pemutil.LoadCertificate(filepath.Join(p.config.Directory, tt.certChainFile))
			require.NoError(t, err)
			require.Equal(t, x509Cert, certChain)

			key, err := pemutil.LoadPrivateKey(filepath.Join(p.config.Directory, tt.keyFile))
			require.NoError(t, err)
			require.Equal(t, x509Key, key)

			bundle, err := pemutil.LoadCertificate(filepath.Join(p.config.Directory, tt.bundleFile))
			require.NoError(t, err)
			require.Equal(t, x509Bundle, bundle)
		})
	}
}

func TestDeleteX509SVID(t *testing.T) {
	baseDir := t.TempDir()

	for _, tt := range []struct {
		name          string
		expectCode    codes.Code
		expectMsg     string
		certChainFile string
		keyFile       string
		bundleFile    string
		existingFiles []string
		expectLogs    []spiretest.LogEntry
	}{
		{
			name:          "Delete X509-SVID (successful - existing files)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
			existingFiles: []string{
				filepath.Join(baseDir, "tls.crt"),
				filepath.Join(baseDir, "tls.key"),
				filepath.Join(baseDir, "ca.crt"),
			},
		},
		{
			name:          "Delete X509-SVID (successful - files already deleted)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			bundleFile:    "ca.crt",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Could not delete certificate chain file. File not found",
					Data: logrus.Fields{
						"file_path": filepath.Join(baseDir, "tls.crt"),
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Could not delete key file. File not found",
					Data: logrus.Fields{
						"file_path": filepath.Join(baseDir, "tls.key"),
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Could not delete bundle file. File not found",
					Data: logrus.Fields{
						"file_path": filepath.Join(baseDir, "ca.crt"),
					},
				},
			},
		},
		{
			name:       "Delete X509-SVID (no cert file name)",
			keyFile:    "tls.key",
			bundleFile: "ca.crt",
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(disk): certchainfile must be specified",
		},
		{
			name:          "Delete X509-SVID (no key file name)",
			certChainFile: "tls.crt",
			bundleFile:    "ca.crt",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): keyfile must be specified",
		},
		{
			name:          "Delete X509-SVID (no bundle file name)",
			certChainFile: "tls.crt",
			keyFile:       "tls.key",
			expectCode:    codes.InvalidArgument,
			expectMsg:     "svidstore(disk): bundlefile must be specified",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, logHook := test.NewNullLogger()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			p := New()
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&configuration{Directory: baseDir}),
				plugintest.Log(log),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)
			createFiles(t, tt.existingFiles)
			err = ss.DeleteX509SVID(ctx, buildMetadata(tt.certChainFile, tt.keyFile, tt.bundleFile))
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
			if tt.expectCode != codes.OK {
				return
			}
			require.NoFileExists(t, filepath.Join(p.config.Directory, tt.bundleFile))
			require.NoError(t, err)
		})
	}
}

func createFiles(t *testing.T, files []string) {
	for _, file := range files {
		f, err := os.Create(file)
		require.NoError(t, err)
		f.Close()
	}
}

func buildMetadata(certChainFile, keyFile, bundleFile string) []string {
	return []string{
		fmt.Sprintf("certchainfile:%s", certChainFile),
		fmt.Sprintf("keyfile:%s", keyFile),
		fmt.Sprintf("bundlefile:%s", bundleFile),
	}
}
