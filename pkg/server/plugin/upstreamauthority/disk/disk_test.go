package disk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestMintX509CA(t *testing.T) {
	key := testkey.NewEC256(t)
	testData := createTestData(t)

	makeCSR := func(spiffeID string) []byte {
		csr, err := util.NewCSRTemplateWithKey(spiffeID, key)
		require.NoError(t, err)
		return csr
	}

	selfSignedCA := Configuration{
		CertFilePath: testData.ECRootCert,
		KeyFilePath:  testData.ECRootKey,
	}
	intermediateCA := Configuration{
		CertFilePath:   testData.ECUpstreamAndIntermediateCert,
		KeyFilePath:    testData.ECUpstreamKey,
		BundleFilePath: testData.ECRootCert,
	}

	for _, tt := range []struct {
		test                    string
		configuration           Configuration
		csr                     []byte
		preferredTTL            time.Duration
		breakConfig             bool
		expectCode              codes.Code
		expectMsgPrefix         string
		expectX509CA            []string
		expectedX509Authorities []string
		expectTTL               time.Duration
	}{
		{
			test:            "empty CSR",
			configuration:   selfSignedCA,
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(disk): unable to sign CSR: unable to parse CSR",
		},
		{
			test:            "malformed CSR",
			configuration:   selfSignedCA,
			csr:             []byte("MALFORMED"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(disk): unable to sign CSR: unable to parse CSR",
		},
		{
			test:            "invalid SPIFFE ID in CSR",
			configuration:   selfSignedCA,
			csr:             makeCSR("invalid://example.org"),
			expectCode:      codes.Internal,
			expectMsgPrefix: `upstreamauthority(disk): unable to sign CSR: CSR with SPIFFE ID "invalid://example.org" is invalid: scheme is missing or invalid`,
		},
		{
			test:                    "valid using self-signed",
			configuration:           selfSignedCA,
			csr:                     makeCSR("spiffe://example.org"),
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CA:            []string{"spiffe://example.org"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			test:                    "valid using intermediate",
			configuration:           intermediateCA,
			csr:                     makeCSR("spiffe://example.org"),
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CA:            []string{"spiffe://example.org", "spiffe://upstream", "spiffe://intermediate"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			test:                    "valid with preferred TTL",
			configuration:           selfSignedCA,
			csr:                     makeCSR("spiffe://example.org"),
			preferredTTL:            x509svid.DefaultUpstreamCATTL + time.Hour,
			expectTTL:               x509svid.DefaultUpstreamCATTL + time.Hour,
			expectX509CA:            []string{"spiffe://example.org"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
		{
			test:                    "valid with already loaded CA",
			configuration:           selfSignedCA,
			csr:                     makeCSR("spiffe://example.org"),
			breakConfig:             true,
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CA:            []string{"spiffe://example.org"},
			expectedX509Authorities: []string{"spiffe://root"},
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			p := New()
			p.clock = testData.Clock

			ua := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), ua,
				plugintest.ConfigureJSON(tt.configuration),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			)

			if tt.breakConfig {
				//	// Modify the cert and key file paths. The CSR will still be
				//	// signed by the cached upstreamCA.
				p.mtx.Lock()
				p.config.CertFilePath = "invalid-file"
				p.config.KeyFilePath = "invalid-file"
				p.mtx.Unlock()
			}

			x509CA, x509Authorities, stream, err := ua.MintX509CA(context.Background(), tt.csr, tt.preferredTTL)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				assert.Nil(t, x509CA)
				assert.Nil(t, x509Authorities)
				assert.Nil(t, stream)
				return
			}

			if assert.NotEmpty(t, x509CA, "x509CA chain is empty") {
				// assert key
				isEqual, err := cryptoutil.PublicKeyEqual(x509CA[0].PublicKey, key.Public())
				if assert.NoError(t, err, "unable to determine key equality") {
					assert.True(t, isEqual, "x509CA key does not match expected key")
				}
				// assert ttl
				ttl := x509CA[0].NotAfter.Sub(testData.Clock.Now())
				assert.Equal(t, tt.expectTTL, ttl, "TTL does not match")
			}
			assert.Equal(t, tt.expectX509CA, certChainURIs(x509CA))
			assert.Equal(t, tt.expectedX509Authorities, authChainURIs(x509Authorities))

			// Plugin does not support streaming back changes so assert the
			// stream returns EOF.
			_, streamErr := stream.RecvUpstreamX509Authorities()
			assert.True(t, errors.Is(streamErr, io.EOF))
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	testData := createTestData(t)
	ua := new(upstreamauthority.V1)
	plugintest.Load(t, BuiltIn(), ua,
		plugintest.ConfigureJSON(Configuration{
			CertFilePath: testData.ECRootCert,
			KeyFilePath:  testData.ECRootKey,
		}),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	pkixBytes, err := x509.MarshalPKIXPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)

	jwtAuthorities, stream, err := ua.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(disk): publishing upstream is unsupported")
	assert.Nil(t, jwtAuthorities)
	assert.Nil(t, stream)
}

func TestConfigure(t *testing.T) {
	testData := createTestData(t)

	for _, tt := range []struct {
		test               string
		certFilePath       string
		keyFilePath        string
		bundleFilePath     string
		overrideCoreConfig *catalog.CoreConfig
		overrideConfig     string
		expectCode         codes.Code
		expectMsgPrefix    string
	}{
		{
			test:         "using EC key",
			certFilePath: testData.ECRootCert,
			keyFilePath:  testData.ECRootKeyAsEC,
		},
		{
			test:         "using PKCS1 key",
			certFilePath: testData.RSARootCert,
			keyFilePath:  testData.RSARootKeyAsPKCS1,
		},
		{
			test:         "using RSA key (PKCS8)",
			certFilePath: testData.ECRootCert,
			keyFilePath:  testData.ECRootKey,
		},
		{
			test:         "using EC key (PKCS8)",
			certFilePath: testData.ECRootCert,
			keyFilePath:  testData.ECRootKey,
		},
		{
			test:            "non matching key and cert",
			certFilePath:    testData.ECRootCert,
			keyFilePath:     testData.RSARootKey,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA: certificate and private key do not match",
		},
		{
			test:            "empty key",
			certFilePath:    testData.ECRootCert,
			keyFilePath:     testData.Empty,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA key: no PEM blocks",
		},
		{
			test:            "empty cert",
			certFilePath:    testData.Empty,
			keyFilePath:     testData.ECRootKey,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA cert: no PEM blocks",
		},
		{
			test:            "unknown key",
			certFilePath:    testData.ECRootCert,
			keyFilePath:     testData.Unknown,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA key: expected block type",
		},
		{
			test:            "unknown cert",
			certFilePath:    testData.Unknown,
			keyFilePath:     testData.ECRootKey,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA cert: expected block type",
		},
		{
			test:            "empty bundle",
			certFilePath:    testData.ECIntermediateCert,
			keyFilePath:     testData.ECIntermediateKey,
			bundleFilePath:  testData.Empty,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA bundle: no PEM blocks",
		},
		{
			test:            "intermediate CA without root bundle",
			certFilePath:    testData.ECIntermediateAndRootCerts,
			keyFilePath:     testData.ECIntermediateKey,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "with no bundle_file_path configured only self-signed CAs are supported",
		},
		{
			test:            "intermediate CA without full chain to root bundle",
			certFilePath:    testData.ECUpstreamCert,
			keyFilePath:     testData.ECUpstreamKey,
			bundleFilePath:  testData.ECRootCert,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA: certificate cannot be validated with the provided bundle",
		},
		{
			test:           "intermediate CA with full chain to root bundle",
			certFilePath:   testData.ECUpstreamAndIntermediateCert,
			keyFilePath:    testData.ECUpstreamKey,
			bundleFilePath: testData.ECRootCert,
		},
		{
			test:            "malformed config",
			overrideConfig:  "MALFORMED",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "plugin configuration is malformed",
		},
		{
			test:               "missing trust domain",
			certFilePath:       testData.ECRootCert,
			keyFilePath:        testData.ECRootKey,
			overrideCoreConfig: &catalog.CoreConfig{},
			expectCode:         codes.InvalidArgument,
			expectMsgPrefix:    "server core configuration must contain trust_domain",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			var err error

			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
			}

			if tt.overrideCoreConfig != nil {
				options = append(options, plugintest.CoreConfig(*tt.overrideCoreConfig))
			} else {
				options = append(options, plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("localhost"),
				}))
			}

			if tt.overrideConfig != "" {
				options = append(options, plugintest.Configure(tt.overrideConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Configuration{
					KeyFilePath:    tt.keyFilePath,
					CertFilePath:   tt.certFilePath,
					BundleFilePath: tt.bundleFilePath,
				}))
			}

			plugintest.Load(t, BuiltIn(), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
		})
	}
}

func certChainURIs(chain []*x509.Certificate) []string {
	var uris []string
	for _, cert := range chain {
		uris = append(uris, certURI(cert))
	}
	return uris
}

func authChainURIs(chain []*x509certificate.X509Authority) []string {
	var uris []string
	for _, authority := range chain {
		uris = append(uris, certURI(authority.Certificate))
	}
	return uris
}

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}

type TestData struct {
	Clock                         *clock.Mock
	ECRootKey                     string
	ECRootKeyAsEC                 string
	ECRootCert                    string
	ECIntermediateKey             string
	ECIntermediateCert            string
	ECUpstreamKey                 string
	ECUpstreamCert                string
	ECUpstreamAndIntermediateCert string
	ECIntermediateAndRootCerts    string
	RSARootKey                    string
	RSARootKeyAsPKCS1             string
	RSARootCert                   string
	Unknown                       string
	Empty                         string
}

func createTestData(t *testing.T) TestData {
	clk := clock.NewMock(t)

	var keys testkey.Keys
	ecRootKey := keys.NewEC256(t)
	ecIntermediateKey := keys.NewEC256(t)
	ecUpstreamKey := keys.NewEC256(t)
	ecRootCert := createCACertificate(t, clk, "spiffe://root", ecRootKey, nil, nil)
	ecIntermediateCert := createCACertificate(t, clk, "spiffe://intermediate", ecIntermediateKey, ecRootCert, ecRootKey)
	ecUpstreamCert := createCACertificate(t, clk, "spiffe://upstream", ecUpstreamKey, ecIntermediateCert, ecIntermediateKey)

	rsaRootKey := keys.NewRSA2048(t)
	rsaRootCert := createCACertificate(t, clk, "spiffe://root", rsaRootKey, nil, nil)

	base := spiretest.TempDir(t)

	testData := TestData{
		Clock:                         clk,
		ECRootKey:                     filepath.Join(base, "ec_root_key.pem"),
		ECRootKeyAsEC:                 filepath.Join(base, "ec_root_key_as_ec.pem"),
		ECRootCert:                    filepath.Join(base, "ec_root_cert.pem"),
		ECIntermediateKey:             filepath.Join(base, "ec_intermediate_key.pem"),
		ECIntermediateCert:            filepath.Join(base, "ec_intermediate_cert.pem"),
		ECUpstreamKey:                 filepath.Join(base, "ec_upstream_key.pem"),
		ECUpstreamCert:                filepath.Join(base, "ec_upstream_cert.pem"),
		ECUpstreamAndIntermediateCert: filepath.Join(base, "ec_upstream_and_intermediate_cert.pem"),
		ECIntermediateAndRootCerts:    filepath.Join(base, "ec_intermediate_and_root.pem"),
		RSARootKey:                    filepath.Join(base, "rsa_root_key.pem"),
		RSARootKeyAsPKCS1:             filepath.Join(base, "rsa_root_key_as_pkcs1.pem"),
		RSARootCert:                   filepath.Join(base, "rsa_root_cert.pem"),
		Unknown:                       filepath.Join(base, "unknown"),
		Empty:                         filepath.Join(base, "empty"),
	}

	writeFile(t, testData.ECRootKey, pkcs8PEM(t, ecRootKey))
	writeFile(t, testData.ECRootKeyAsEC, ecPEM(t, ecRootKey))
	writeFile(t, testData.ECRootCert, certPEM(ecRootCert))
	writeFile(t, testData.ECIntermediateKey, pkcs8PEM(t, ecIntermediateKey))
	writeFile(t, testData.ECIntermediateCert, certPEM(ecIntermediateCert))
	writeFile(t, testData.ECUpstreamKey, pkcs8PEM(t, ecUpstreamKey))
	writeFile(t, testData.ECUpstreamCert, certPEM(ecUpstreamCert))
	writeFile(t, testData.ECUpstreamAndIntermediateCert, certPEM(ecUpstreamCert, ecIntermediateCert))
	writeFile(t, testData.ECIntermediateAndRootCerts, certPEM(ecIntermediateCert, ecRootCert))
	writeFile(t, testData.RSARootKey, pkcs8PEM(t, rsaRootKey))
	writeFile(t, testData.RSARootKeyAsPKCS1, pkcs1PEM(t, rsaRootKey))
	writeFile(t, testData.RSARootCert, certPEM(rsaRootCert))
	writeFile(t, testData.Unknown, pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN"}))
	writeFile(t, testData.Empty, nil)
	return testData
}

func createCACertificate(t *testing.T, clk clock.Clock, uri string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	now := clk.Now()

	u, err := url.Parse(uri)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		URIs:                  []*url.URL{u},
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return testca.CreateCertificate(t, tmpl, parent, key.Public(), parentKey)
}

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	data, err := pemutil.EncodePKCS8PrivateKey(key)
	require.NoError(t, err)
	return data
}

func pkcs1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	data, err := pemutil.EncodeRSAPrivateKey(key)
	require.NoError(t, err)
	return data
}

func ecPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	data, err := pemutil.EncodeECPrivateKey(key)
	require.NoError(t, err)
	return data
}

func certPEM(certs ...*x509.Certificate) []byte {
	return pemutil.EncodeCertificates(certs)
}

func writeFile(t *testing.T, path string, data []byte) {
	err := os.WriteFile(path, data, 0600)
	require.NoError(t, err)
}
