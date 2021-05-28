package disk

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestMintX509CA(t *testing.T) {
	// On OSX
	// openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem
	// openssl req -days 3650 -x509 -new -key root_key.pem -out root_cert.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://root\nbasicConstraints=CA:true") -extensions v3
	// openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem
	// openssl req  -new -key intermediate_key.pem -out intermediate_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
	// openssl x509 -days 3650 -req -CA root_cert.pem -CAkey root_key.pem -in intermediate_csr.pem -out intermediate_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
	// openssl ecparam -name prime256v1 -genkey -noout -out upstream_key.pem
	// openssl req  -new -key upstream_key.pem -out upstream_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	// openssl x509 -days 3650 -req -CA intermediate_cert.pem -CAkey intermediate_key.pem -in upstream_csr.pem -out upstream_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://upstream\nbasicConstraints=CA:true") -extensions v3
	// cat upstream_cert.pem intermediate_cert.pem > upstream_and_intermediate.pem
	// This test verifies the cert chain and will start failing on May 15 2029

	key := testkey.NewEC256(t)
	clock := clock.NewMock(t)

	makeCSR := func(spiffeID string) []byte {
		csr, err := util.NewCSRTemplateWithKey(spiffeID, key)
		require.NoError(t, err)
		return csr
	}

	selfSignedCA := Configuration{
		CertFilePath: "testdata/keys/EC/cert.pem",
		KeyFilePath:  "testdata/keys/EC/private_key.pem",
	}
	intermediateCA := Configuration{
		CertFilePath:   "testdata/keys/EC/upstream_and_intermediate.pem",
		KeyFilePath:    "testdata/keys/EC/upstream_key.pem",
		BundleFilePath: "testdata/keys/EC/root_cert.pem",
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
			expectMsgPrefix: `upstreamauthority(disk): unable to sign CSR: "invalid://example.org" is not a valid trust domain SPIFFE ID`,
		},
		{
			test:            "invalid SPIFFE ID in CSR",
			configuration:   selfSignedCA,
			csr:             makeCSR("invalid://example.org"),
			expectCode:      codes.Internal,
			expectMsgPrefix: `upstreamauthority(disk): unable to sign CSR: "invalid://example.org" is not a valid trust domain SPIFFE ID`,
		},
		{
			test:                    "valid using self-signed",
			configuration:           selfSignedCA,
			csr:                     makeCSR("spiffe://example.org"),
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CA:            []string{"spiffe://example.org"},
			expectedX509Authorities: []string{"spiffe://local"},
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
			expectedX509Authorities: []string{"spiffe://local"},
		},
		{
			test:                    "valid with already loaded CA",
			configuration:           selfSignedCA,
			csr:                     makeCSR("spiffe://example.org"),
			breakConfig:             true,
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CA:            []string{"spiffe://example.org"},
			expectedX509Authorities: []string{"spiffe://local"},
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			p := New()
			p.clock = clock

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
				ttl := x509CA[0].NotAfter.Sub(clock.Now())
				assert.Equal(t, tt.expectTTL, ttl, "TTL does not match")
			}
			assert.Equal(t, tt.expectX509CA, certChainURIs(x509CA))
			assert.Equal(t, tt.expectedX509Authorities, certChainURIs(x509Authorities))

			// Plugin does not support streaming back changes so assert the
			// stream returns EOF.
			_, streamErr := stream.RecvUpstreamX509Authorities()
			assert.True(t, errors.Is(streamErr, io.EOF))
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	ua := new(upstreamauthority.V1)
	plugintest.Load(t, BuiltIn(), ua,
		plugintest.ConfigureJSON(Configuration{
			CertFilePath: "testdata/keys/EC/cert.pem",
			KeyFilePath:  "testdata/keys/EC/private_key.pem",
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
			certFilePath: "testdata/keys/EC/cert.pem",
			keyFilePath:  "testdata/keys/EC/private_key.pem",
		},
		{
			test:         "using PKCS1 key",
			certFilePath: "testdata/keys/PKCS1/cert.pem",
			keyFilePath:  "testdata/keys/PKCS1/private_key.pem",
		},
		{
			test:         "using PKCS8 key",
			certFilePath: "testdata/keys/PKCS8/cert.pem",
			keyFilePath:  "testdata/keys/PKCS8/private_key.pem",
		},
		{
			test:            "non matching key and cert",
			certFilePath:    "testdata/keys/PKCS8/cert.pem",
			keyFilePath:     "testdata/keys/PKCS1/private_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA: certificate and private key do not match",
		},
		{
			test:            "empty key",
			certFilePath:    "testdata/keys/EC/cert.pem",
			keyFilePath:     "testdata/keys/empty/private_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA key: no PEM blocks",
		},
		{
			test:            "empty cert",
			certFilePath:    "testdata/keys/empty/cert.pem",
			keyFilePath:     "testdata/keys/EC/private_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA cert: no PEM blocks",
		},
		{
			test:            "unknown key",
			certFilePath:    "testdata/keys/EC/cert.pem",
			keyFilePath:     "testdata/keys/unknown/private_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA key: expected block type",
		},
		{
			test:            "unknown cert",
			certFilePath:    "testdata/keys/unknown/cert.pem",
			keyFilePath:     "testdata/keys/EC/private_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA cert: unable to parse",
		},
		{
			test:            "empty bundle",
			certFilePath:    "testdata/keys/EC/cert.pem",
			keyFilePath:     "testdata/keys/EC/private_key.pem",
			bundleFilePath:  "testdata/keys/empty/cert.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA bundle: no PEM blocks",
		},
		{
			test:            "intermediate CA without root bundle",
			certFilePath:    "testdata/keys/EC/upstream_and_intermediate.pem",
			keyFilePath:     "testdata/keys/EC/upstream_key.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "with no bundle_file_path configured only self-signed CAs are supported",
		},
		{
			test:            "intermediate CA without full chain to root bundle",
			certFilePath:    "testdata/keys/EC/upstream_cert.pem",
			keyFilePath:     "testdata/keys/EC/upstream_key.pem",
			bundleFilePath:  "testdata/keys/EC/root_cert.pem",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to load upstream CA: certificate cannot be validated with the provided bundle",
		},
		{
			test:           "intermediate CA with full chain to root bundle",
			certFilePath:   "testdata/keys/EC/upstream_and_intermediate.pem",
			keyFilePath:    "testdata/keys/EC/upstream_key.pem",
			bundleFilePath: "testdata/keys/EC/root_cert.pem",
		},
		{
			test:            "malformed config",
			overrideConfig:  "MALFORMED",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration: ",
		},
		{
			test:               "missing trust domain",
			certFilePath:       "testdata/keys/EC/cert.pem",
			keyFilePath:        "testdata/keys/EC/private_key.pem",
			overrideCoreConfig: &catalog.CoreConfig{},
			expectCode:         codes.InvalidArgument,
			expectMsgPrefix:    "trust_domain is required",
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

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}
