package evidenkms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	kmip "github.com/Cosmian/kmip-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// ─── Configure ───────────────────────────────────────────────────────────────

func TestConfigure(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()

	for _, tt := range []struct {
		name       string
		config     string
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "valid token auth",
			config: fmt.Sprintf(`
				kms_addr            = %q
				ca_key_uid          = "ca-key-001"
				insecure_skip_verify = true
				token_auth { token = "test-token" }
			`, f.URL()),
			expectCode: codes.OK,
		},
		{
			name:       "missing kms_addr",
			config:     `ca_key_uid = "k" token_auth { token = "x" }`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "kms_addr",
		},
		{
			name: "missing ca_key_uid",
			config: fmt.Sprintf(`kms_addr = %q
				token_auth { token = "x" }
			`, f.URL()),
			expectCode: codes.InvalidArgument,
			expectMsg:  "ca_key_uid",
		},
		{
			name: "both auth methods",
			config: fmt.Sprintf(`
				kms_addr   = %q
				ca_key_uid = "k"
				token_auth { token = "a" }
				cert_auth  { client_cert_path = "x" client_key_path = "y" }
			`, f.URL()),
			expectCode: codes.InvalidArgument,
			expectMsg:  "cert_auth and token_auth are mutually exclusive",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var configErr error
			plugintest.Load(t, builtinUA(p), nil,
				plugintest.CaptureConfigureError(&configErr),
				plugintest.Configure(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			)
			spiretest.RequireGRPCStatusHasPrefix(t, configErr, tt.expectCode, tt.expectMsg)
		})
	}
}

// ─── MintX509CA ───────────────────────────────────────────────────────────────

func TestMintX509CA(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()

	// Inject a fake CA private key and certificate into the fake store.
	caKeyUID := "ca-private-key-001"
	caCertPEM := fakeSelfSignedCACert(t)
	f.InjectObject(caKeyUID, "PrivateKey", []string{"vault_pki_ca"}, nil, nil)
	f.InjectObject("ca-cert-001", "Certificate", nil, nil, []byte(caCertPEM))

	v1 := loadUAPlugin(t, f, caKeyUID)

	// Generate a fake CSR DER.
	csrDER := fakeCSRDER(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	x509CAChain, x509Authorities, stream, err := v1.MintX509CA(ctx, csrDER, 0)
	require.NoError(t, err)
	require.NotNil(t, stream)
	require.NotEmpty(t, x509CAChain)
	_ = x509Authorities
	stream.Close()
}

func TestMintX509CANotConfigured(t *testing.T) {
	p := New()
	err := p.MintX509CAAndSubscribe(
		&upstreamauthorityv1.MintX509CARequest{Csr: []byte("invalid")},
		nil,
	)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func loadUAPlugin(t *testing.T, f *kmip.FakeKMS, caKeyUID string) *upstreamauthority.V1 {
	t.Helper()
	p := New()
	v1 := new(upstreamauthority.V1)
	plugintest.Load(t, builtinUA(p), v1,
		plugintest.Configure(fmt.Sprintf(`
			kms_addr            = %q
			ca_key_uid          = %q
			insecure_skip_verify = true
			token_auth { token = "test-token" }
		`, f.URL(), caKeyUID)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	return v1
}

func builtinUA(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func fakeCSRDER(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csr := &x509.CertificateRequest{}
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
	require.NoError(t, err)
	return derBytes
}

func fakeSelfSignedCACert(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}
