package kmip

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"

	ovh "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const testCAKeyUID = "ca-key-001"

// ─── Configure ───────────────────────────────────────────────────────────────

func TestConfigure(t *testing.T) {
	store := newUAFakeStore(t)
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	caFile := writeTempPEM(t, caPEM)

	for _, tt := range []struct {
		name       string
		config     string
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "valid config",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				ca_cert_path         = %q
				insecure_skip_verify = true
				ca_key_uid           = %q
			`, addr, caFile, testCAKeyUID),
			expectCode: codes.OK,
		},
		{
			name:       "missing kmip_addr",
			config:     `insecure_skip_verify = true`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "kmip_addr",
		},
		{
			name:       "missing ca_key_uid",
			config:     fmt.Sprintf(`kmip_addr = %q insecure_skip_verify = true`, addr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "ca_key_uid",
		},
		{
			name: "key path set but no cert path",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				ca_key_uid           = %q
				client_key_path      = "some.key"
				insecure_skip_verify = true
			`, addr, testCAKeyUID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "client_cert_path",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var configErr error
			plugintest.Load(t, builtin(p), nil,
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

// ─── MintX509CA ──────────────────────────────────────────────────────────────

func TestMintX509CA(t *testing.T) {
	store := newUAFakeStore(t)
	addr, caPEM := kmiptest.NewServer(t, store.handler())

	v1 := loadUAPlugin(t, addr, caPEM, "")

	csrDER := fakeCSRDER(t)
	ctx := t.Context()

	x509CAChain, x509Roots, stream, err := v1.MintX509CA(ctx, csrDER, 0)
	require.NoError(t, err)
	require.NotNil(t, stream)
	require.NotEmpty(t, x509CAChain)
	require.NotEmpty(t, x509Roots)
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

func loadUAPlugin(t *testing.T, addr, caPEM, caCertUID string) *upstreamauthority.V1 {
	t.Helper()
	caFile := writeTempPEM(t, caPEM)
	p := New()
	v1 := new(upstreamauthority.V1)

	var config string
	if caCertUID != "" {
		config = fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			ca_key_uid           = %q
			ca_cert_uid          = %q
		`, addr, caFile, testCAKeyUID, caCertUID)
	} else {
		config = fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			ca_key_uid           = %q
		`, addr, caFile, testCAKeyUID)
	}

	plugintest.Load(t, builtin(p), v1,
		plugintest.Configure(config),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	return v1
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

func writeTempPEM(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ─── uaFakeStore ─── in-memory KMIP server for UpstreamAuthority tests ───────

// uaFakeStore holds a CA key+cert and handles Certify and Get requests.
type uaFakeStore struct {
	mu        sync.Mutex
	caPriv    *rsa.PrivateKey
	caCert    *x509.Certificate
	caCertDER []byte
	certs     map[string][]byte // uid → DER cert
	certUID   string
}

func newUAFakeStore(t *testing.T) *uaFakeStore {
	t.Helper()
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	return &uaFakeStore{
		caPriv:    caPriv,
		caCert:    caCert,
		caCertDER: derBytes,
		certs:     make(map[string][]byte),
		certUID:   "ca-cert-001",
	}
}

func (s *uaFakeStore) handler() kmipserver.RequestHandler {
	exec := kmipserver.NewBatchExecutor()
	exec.SetSupportedProtocolVersions(ovh.V2_1, ovh.V1_4)

	// DiscoverVersions (needed for version negotiation).
	exec.Route(ovh.OperationDiscoverVersions, kmipserver.HandleFunc(func(_ context.Context, req *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
		return &payloads.DiscoverVersionsResponsePayload{
			// Advertise both 2.1 and 1.4 — the UpstreamAuthority plugin enforces 2.1.
			ProtocolVersion: []ovh.ProtocolVersion{ovh.V2_1, ovh.V1_4},
		}, nil
	}))

	// Certify — sign the CSR with our CA key.
	exec.Route(ovh.OperationCertify, kmipserver.HandleFunc(func(_ context.Context, req *CertifyRequestPayload) (*CertifyResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()

		csr, err := x509.ParseCertificateRequest(req.CertificateRequestValue)
		if err != nil {
			return nil, fmt.Errorf("parse CSR: %w", err)
		}

		template := &x509.Certificate{
			SerialNumber:          big.NewInt(42),
			Subject:               csr.Subject,
			PublicKey:             csr.PublicKey,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		signed, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caPriv)
		if err != nil {
			return nil, fmt.Errorf("sign cert: %w", err)
		}

		uid := fmt.Sprintf("cert-%d", len(s.certs)+1)
		s.certs[uid] = signed
		// Add a CertificateLink back to the CA cert.
		return &CertifyResponsePayload{UniqueIdentifier: uid}, nil
	}))

	// Get — return DER-encoded certificate.
	exec.Route(ovh.OperationGet, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()

		// Signed certificate objects.
		if der, ok := s.certs[req.UniqueIdentifier]; ok {
			return &payloads.GetResponsePayload{
				ObjectType:       ovh.ObjectTypeCertificate,
				UniqueIdentifier: req.UniqueIdentifier,
				Object: &ovh.Certificate{
					CertificateType:  ovh.CertificateTypeX_509,
					CertificateValue: der,
				},
			}, nil
		}
		// CA certificate.
		if req.UniqueIdentifier == s.certUID {
			return &payloads.GetResponsePayload{
				ObjectType:       ovh.ObjectTypeCertificate,
				UniqueIdentifier: s.certUID,
				Object: &ovh.Certificate{
					CertificateType:  ovh.CertificateTypeX_509,
					CertificateValue: s.caCertDER,
				},
			}, nil
		}
		return nil, fmt.Errorf("object %s not found", req.UniqueIdentifier)
	}))

	// GetAttributes — return CertificateLink.
	exec.Route(ovh.OperationGetAttributes, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var attrs []ovh.Attribute
		if _, ok := s.certs[req.UniqueIdentifier]; ok {
			for _, want := range req.AttributeName {
				if want == ovh.AttributeNameLink {
					attrs = append(attrs, ovh.Attribute{
						AttributeName: ovh.AttributeNameLink,
						AttributeValue: ovh.Link{
							LinkType:               ovh.LinkTypeCertificateLink,
							LinkedObjectIdentifier: s.certUID,
						},
					})
				}
			}
		}
		return &payloads.GetAttributesResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        attrs,
		}, nil
	}))

	return exec
}
