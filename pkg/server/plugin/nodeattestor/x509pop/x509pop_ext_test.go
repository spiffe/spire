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
	"strconv"
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
	var id asn1.ObjectIdentifier
	for arc := range strings.SplitSeq(oid, ".") {
		n, err := strconv.Atoi(arc)
		require.NoError(t, err)
		id = append(id, n)
	}
	return pkix.Extension{Id: id, Value: value}
}

func stringExt(t *testing.T, oid, value, params string) pkix.Extension {
	v, err := asn1.MarshalWithParams(value, params)
	require.NoError(t, err)
	return rawExt(t, oid, v)
}

func utf8Ext(t *testing.T, oid, value string) pkix.Extension {
	return stringExt(t, oid, value, "utf8")
}

func critical(ext pkix.Extension) pkix.Extension {
	ext.Critical = true
	return ext
}

func extSelector(oid, value string) string {
	return "ext:oid:" + oid + ":" + value
}

// valueOfLength returns a value that makes the selector for oid n characters long.
func valueOfLength(oid string, n int) string {
	return strings.Repeat("a", n-len(extSelector(oid, "")))
}

type extTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	path string
}

func newExtTestCA(t *testing.T) *extTestCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return &extTestCA{cert: cert, key: key, path: path}
}

// attest issues a leaf with exts and returns its selectors, with extension_oids set to oids.
func (ca *extTestCA) attest(t *testing.T, exts []pkix.Extension, oids ...string) ([]string, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(0x4d8),
		Subject:         pkix.Name{CommonName: "node1.example.org"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: exts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.cert, &leafKey.PublicKey, ca.key)
	require.NoError(t, err)

	quoted := make([]string, 0, len(oids))
	for _, oid := range oids {
		quoted = append(quoted, fmt.Sprintf("%q", oid))
	}
	config := fmt.Sprintf(`
ca_bundle_path = %q
agent_path_template = "/x509pop/{{ .Subject.CommonName }}"
extension_oids = [%s]
`, ca.path, strings.Join(quoted, ", "))

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
	if err != nil {
		return nil, err
	}
	require.Equal(t, "spiffe://example.org/spire/agent/x509pop/node1.example.org", result.AgentID)

	var got []string
	for _, sel := range result.Selectors {
		require.Equal(t, "x509pop", sel.Type)
		got = append(got, sel.Value)
	}
	return got, nil
}

func (ca *extTestCA) baseSelectors() []string {
	return []string{
		"subject:cn:node1.example.org",
		"ca:fingerprint:" + x509pop.Fingerprint(ca.cert),
		"serialnumber:04d8",
	}
}

func TestAttestExtensionSelectors(t *testing.T) {
	ca := newExtTestCA(t)

	notString, err := asn1.Marshal(42)
	require.NoError(t, err)

	maxValue := valueOfLength(oidMax, 255)
	oversizedValue := valueOfLength(oidOversized, 256)

	got, err := ca.attest(t, []pkix.Extension{
		utf8Ext(t, oidRole, "web"),
		utf8Ext(t, oidEnvironment, "staging"),
		utf8Ext(t, oidRack, "r12"),                                  // not configured
		rawExt(t, oidTeam, notString),                               // not a string
		rawExt(t, oidBMP, []byte{0x1e, 0x04, 0x00, 'h', 0x00, 'i'}), // BMPString
		rawExt(t, oidT61, []byte{0x14, 0x02, 'h', 'i'}),             // T61String
		stringExt(t, oidPrintable, "dc1", "printable"),
		stringExt(t, oidIA5, "rack-7", "ia5"),
		utf8Ext(t, oidMax, maxValue),
		utf8Ext(t, oidOversized, oversizedValue),
	}, oidRole, oidEnvironment, oidTeam, oidBMP, oidT61, oidPrintable, oidIA5, oidMax, oidOversized)
	require.NoError(t, err)

	require.ElementsMatch(t, append(ca.baseSelectors(),
		extSelector(oidRole, "web"),
		extSelector(oidEnvironment, "staging"),
		extSelector(oidPrintable, "dc1"),
		extSelector(oidIA5, "rack-7"),
		extSelector(oidMax, maxValue),
	), got)
}

func TestAttestCriticalExtensionSelectors(t *testing.T) {
	ca := newExtTestCA(t)

	notString, err := asn1.Marshal(42)
	require.NoError(t, err)

	for _, tt := range []struct {
		name      string
		ext       pkix.Extension
		oids      []string
		selectors []string
		expectErr bool
	}{
		{
			name:      "configured and usable",
			ext:       critical(utf8Ext(t, oidRole, "web")),
			oids:      []string{oidRole},
			selectors: []string{extSelector(oidRole, "web")},
		},
		{
			name:      "configured but not a string",
			ext:       critical(rawExt(t, oidRole, notString)),
			oids:      []string{oidRole},
			expectErr: true,
		},
		{
			name:      "configured but oversized",
			ext:       critical(utf8Ext(t, oidRole, valueOfLength(oidRole, 256))),
			oids:      []string{oidRole},
			expectErr: true,
		},
		{
			name:      "not configured",
			ext:       critical(utf8Ext(t, oidRole, "web")),
			oids:      []string{oidEnvironment},
			expectErr: true,
		},
		{
			name:      "no extension_oids",
			ext:       critical(utf8Ext(t, oidRole, "web")),
			expectErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ca.attest(t, []pkix.Extension{tt.ext}, tt.oids...)
			if tt.expectErr {
				spiretest.RequireGRPCStatusContains(t, err, codes.PermissionDenied, "unhandled critical extension")
				return
			}
			require.NoError(t, err)
			require.ElementsMatch(t, append(ca.baseSelectors(), tt.selectors...), got)
		})
	}
}

func TestConfigureExtensionOIDs(t *testing.T) {
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
		require.NoError(t, doConfig(t, `extension_oids = ["1.3.6.1.4.1.32473.1.1", "1.3.6.1.4.1.32473.1.2"]`))
	})
	t.Run("duplicate", func(t *testing.T) {
		require.NoError(t, doConfig(t, `extension_oids = ["1.3.6.1.4.1.32473.1.1", "1.3.6.1.4.1.32473.1.1"]`))
	})
	for _, oid := range []string{"role", "1", "3.1", "1.40", "1.03.6.1", "+1.3.6.1", "1..3"} {
		t.Run("bad oid "+oid, func(t *testing.T) {
			err := doConfig(t, fmt.Sprintf("extension_oids = [%q]", oid))
			spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "invalid extension_oids entry")
		})
	}
}
