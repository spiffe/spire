package svidstore_test

import (
	"crypto/x509"
	"testing"

	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
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
	x509FederatedBundlePem = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`
)

func TestParseMetadata(t *testing.T) {
	for _, tt := range []struct {
		name       string
		expect     map[string]string
		secretData []string
		expectErr  string
	}{
		{
			name: "multiples selectors",
			secretData: []string{
				"a:1",
				"b:2",
				"c:3",
			},
			expect: map[string]string{
				"a": "1",
				"b": "2",
				"c": "3",
			},
		},
		{
			name:       "no data",
			secretData: []string{},
			expect:     map[string]string{},
		},
		{
			name:       "invalid data",
			secretData: []string{"invalid"},
			expectErr:  `metadata does not contain a colon: "invalid"`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			result, err := svidstore.ParseMetadata(tt.secretData)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				require.Nil(t, result)

				return
			}
			require.Equal(t, tt.expect, result)
			require.NoError(t, err)
		})
	}
}

func TestSecretFromProto(t *testing.T) {
	x509Cert, err := pemutil.ParseCertificate([]byte(x509CertPem))
	require.NoError(t, err)

	x509Bundle, err := pemutil.ParseCertificate([]byte(x509BundlePem))
	require.NoError(t, err)

	federatedBundle, err := pemutil.ParseCertificate([]byte(x509FederatedBundlePem))
	require.NoError(t, err)

	x509Key, err := pemutil.ParseECPrivateKey([]byte(x509KeyPem))
	require.NoError(t, err)

	keyByte, err := x509.MarshalPKCS8PrivateKey(x509Key)
	require.NoError(t, err)

	for _, tt := range []struct {
		name   string
		req    *svidstorev1.PutX509SVIDRequest
		err    string
		expect *svidstore.Data
	}{
		{
			name: "success",
			req: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/foo",
					CertChain:  [][]byte{x509Cert.Raw},
					PrivateKey: keyByte,
					Bundle:     [][]byte{x509Bundle.Raw},
				},
				Metadata: []string{
					"a:1",
					"b:2",
				},
				FederatedBundles: map[string][]byte{
					"federated1": federatedBundle.Raw,
					"federated2": federatedBundle.Raw,
				},
			},
			expect: &svidstore.Data{
				SPIFFEID:    "spiffe://example.org/foo",
				X509SVID:    x509CertPem,
				X509SVIDKey: x509KeyPem,
				Bundle:      x509BundlePem,
				FederatedBundles: map[string]string{
					"federated1": x509FederatedBundlePem,
					"federated2": x509FederatedBundlePem,
				},
			},
		},
		{
			name: "failed to parse cert chain",
			req: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/foo",
					CertChain:  [][]byte{{1}},
					PrivateKey: keyByte,
					Bundle:     [][]byte{x509Bundle.Raw},
				},
				Metadata: []string{
					"a:1",
					"b:2",
				},
				FederatedBundles: map[string][]byte{
					"federated1": federatedBundle.Raw,
					"federated2": federatedBundle.Raw,
				},
			},
			err: "failed to parse CertChain: x509: malformed certificate",
		},
		{
			name: "failed to parse bundle",
			req: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/foo",
					CertChain:  [][]byte{x509Cert.Raw},
					PrivateKey: keyByte,
					Bundle:     [][]byte{{1}},
				},
				Metadata: []string{
					"a:1",
					"b:2",
				},
				FederatedBundles: map[string][]byte{
					"federated1": federatedBundle.Raw,
					"federated2": federatedBundle.Raw,
				},
			},
			err: "failed to parse Bundle: x509: malformed certificate",
		},
		{
			name: "failed to parse key",
			req: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/foo",
					CertChain:  [][]byte{x509Cert.Raw},
					PrivateKey: []byte{1},
					Bundle:     [][]byte{x509Bundle.Raw},
				},
				Metadata: []string{
					"a:1",
					"b:2",
				},
				FederatedBundles: map[string][]byte{
					"federated1": federatedBundle.Raw,
					"federated2": federatedBundle.Raw,
				},
			},
			err: "failed to parse key: asn1: syntax error: truncated tag or length",
		},
		{
			name: "failed to parse federated bundle",
			req: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/foo",
					CertChain:  [][]byte{x509Cert.Raw},
					PrivateKey: keyByte,
					Bundle:     [][]byte{x509Bundle.Raw},
				},
				Metadata: []string{
					"a:1",
					"b:2",
				},
				FederatedBundles: map[string][]byte{
					"federated1": {1},
				},
			},
			err: "failed to parse FederatedBundle \"federated1\": x509: malformed certificate",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svidstore.SecretFromProto(tt.req)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, resp)
		})
	}
}
