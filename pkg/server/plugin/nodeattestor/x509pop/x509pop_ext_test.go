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
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/fixture"
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
	oidBMP         = "1.3.6.1.4.1.32473.1.5"
	oidT61         = "1.3.6.1.4.1.32473.1.6"
	oidPrintable   = "1.3.6.1.4.1.32473.1.7"
	oidIA5         = "1.3.6.1.4.1.32473.1.8"
	oidMax         = "1.3.6.1.4.1.32473.1.9"
	oidOversized   = "1.3.6.1.4.1.32473.1.10"
)

func rawExt(t *testing.T, oid string, value []byte) pkix.Extension {
	parsed, err := parseOID(oid)
	require.NoError(t, err)
	return pkix.Extension{Id: parsed, Value: value}
}

func stringExt(t *testing.T, oid, value, params string) pkix.Extension {
	v, err := asn1.MarshalWithParams(value, params)
	require.NoError(t, err)
	return rawExt(t, oid, v)
}

func utf8Ext(t *testing.T, oid, value string) pkix.Extension {
	return stringExt(t, oid, value, "utf8")
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

	// "ext:max:" is 8 characters, so these values make selectors of 255 and 256 characters.
	maxValue := strings.Repeat("a", 247)
	oversizedValue := strings.Repeat("a", 242)

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
			utf8Ext(t, oidRack, "r12"),                                  // not configured
			rawExt(t, oidTeam, notString),                               // not a string
			rawExt(t, oidBMP, []byte{0x1e, 0x04, 0x00, 'h', 0x00, 'i'}), // BMPString
			rawExt(t, oidT61, []byte{0x14, 0x02, 'h', 'i'}),             // T61String
			stringExt(t, oidPrintable, "dc1", "printable"),
			stringExt(t, oidIA5, "rack-7", "ia5"),
			utf8Ext(t, oidMax, maxValue),
			utf8Ext(t, oidOversized, oversizedValue), // "ext:oversized:" is 14 characters, 256 in total
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
  %q = "bmp"
  %q = "t61"
  %q = "printable"
  %q = "ia5"
  %q = "max"
  %q = "oversized"
}
`, caPath, oidRole, oidEnvironment, oidTeam, oidBMP, oidT61, oidPrintable, oidIA5, oidMax, oidOversized)

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
		"ext:printable:dc1",
		"ext:ia5:rack-7",
		"ext:max:" + maxValue,
	}, got)
	require.Len(t, "ext:max:"+maxValue, 255)
	require.Len(t, "ext:oversized:"+oversizedValue, 256)
}

func TestConfigureExtensionSelectors(t *testing.T) {
	caPath := fixture.Join("nodeattestor", "x509pop", "root-crt.pem")
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
	for _, tt := range []struct {
		oid    string
		expect string
	}{
		{oid: "role", expect: "invalid arc"},
		{oid: "1", expect: "not a valid ASN.1 object identifier"},
		{oid: "3.1", expect: "not a valid ASN.1 object identifier"},
		{oid: "1.40", expect: "not a valid ASN.1 object identifier"},
		{oid: "1.03.6.1", expect: "canonical dotted decimal form"},
		{oid: "+1.3.6.1", expect: "canonical dotted decimal form"},
		{oid: "1..3", expect: "invalid arc"},
	} {
		t.Run("bad oid "+tt.oid, func(t *testing.T) {
			err := doConfig(t, fmt.Sprintf("extension_selectors = { %q = \"role\" }", tt.oid))
			spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "invalid extension_selectors OID")
			spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, tt.expect)
		})
	}
	t.Run("bad name", func(t *testing.T) {
		err := doConfig(t, `extension_selectors = { "1.3.6.1.4.1.32473.1.1" = "ro:le" }`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "must match [A-Za-z0-9_-]+")
	})
}
