package x509pop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	// 32473 is the IANA private enterprise number reserved for documentation (RFC 5612).
	oidRole        = "1.3.6.1.4.1.32473.1.1"
	oidEnvironment = "1.3.6.1.4.1.32473.1.2"
	oidTeam        = "1.3.6.1.4.1.32473.1.3"
	oidRack        = "1.3.6.1.4.1.32473.1.4"
)

func utf8Ext(t *testing.T, oid, value string) pkix.Extension {
	parsed, err := parseOID(oid)
	require.NoError(t, err)
	v, err := asn1.MarshalWithParams(value, "utf8")
	require.NoError(t, err)
	return pkix.Extension{Id: parsed, Value: v}
}

func TestAttestExtensionSelectors(t *testing.T) {
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	notString, err := asn1.Marshal(42)
	require.NoError(t, err)
	notStringOID, err := parseOID(oidTeam)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x4d8),
		Subject:      pkix.Name{CommonName: "node1.example.org"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			utf8Ext(t, oidRole, "web"),
			utf8Ext(t, oidEnvironment, "staging"),
			utf8Ext(t, oidRack, "r12"),           // not configured
			{Id: notStringOID, Value: notString}, // configured, but not a string
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	config := fmt.Sprintf(`
ca_bundle_path = %q
agent_path_template = "/x509pop/{{ .Subject.CommonName }}"
extension_selectors = {
  %q = "role"
  %q = "environment"
  %q = "team"
}
`, caPath, oidRole, oidEnvironment, oidTeam)

	v1 := new(nodeattestor.V1)
	plugintest.Load(t, BuiltIn(), v1,
		plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(config),
	)

	payload := marshal(t, &x509pop.AttestationData{Certificates: [][]byte{leafDER}})
	result, err := v1.Attest(context.Background(), payload, func(_ context.Context, challenge []byte) ([]byte, error) {
		c := new(x509pop.Challenge)
		unmarshal(t, challenge, c)
		resp, err := x509pop.CalculateResponse(leafKey, c)
		require.NoError(t, err)
		return marshal(t, resp), nil
	})
	require.NoError(t, err)
	require.Equal(t, "spiffe://example.org/spire/agent/x509pop/node1.example.org", result.AgentID)

	var got []string
	for _, sel := range result.Selectors {
		require.Equal(t, "x509pop", sel.Type)
		got = append(got, sel.Value)
	}
	require.ElementsMatch(t, []string{
		"subject:cn:node1.example.org",
		"ca:fingerprint:" + x509pop.Fingerprint(caCert),
		"serialnumber:04d8",
		"ext:role:web",
		"ext:environment:staging",
	}, got)
}

func TestConfigureExtensionSelectors(t *testing.T) {
	caPath := filepath.Join("..", "..", "..", "..", "..", "test", "fixture", "nodeattestor", "x509pop", "root-crt.pem")
	doConfig := func(t *testing.T, extra string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
			plugintest.CaptureConfigureError(&err),
			plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			plugintest.Configure(fmt.Sprintf("ca_bundle_path = %q\n%s", caPath, extra)),
		)
		return err
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, doConfig(t, `extension_selectors = { "1.3.6.1.4.1.32473.1.1" = "role" }`))
	})
	t.Run("bad oid", func(t *testing.T) {
		err := doConfig(t, `extension_selectors = { "role" = "role" }`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "invalid extension_selectors OID")
	})
	t.Run("bad name", func(t *testing.T) {
		err := doConfig(t, `extension_selectors = { "1.3.6.1.4.1.32473.1.1" = "ro:le" }`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "invalid extension_selectors name")
	})
}
