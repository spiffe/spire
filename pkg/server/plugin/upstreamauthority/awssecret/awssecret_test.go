package awssecret

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		test               string
		overrideCoreConfig *catalog.CoreConfig
		overrideConfig     string
		expectCode         codes.Code
		expectMsgPrefix    string

		// All allowed configurations
		region          string
		certFileARN     string
		keyFileARN      string
		accessKeyID     string
		secretAccessKey string
		securityToken   string
		assumeRoleARN   string
	}{
		{
			test:            "success",
			region:          "region_1",
			certFileARN:     "cert",
			keyFileARN:      "key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
		},
		{
			test:            "malformed configuration",
			overrideConfig:  "MALFORMED",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
		},
		{
			test:               "no trust domain",
			overrideCoreConfig: &catalog.CoreConfig{},
			expectCode:         codes.InvalidArgument,
			expectMsgPrefix:    "trust_domain is required",
		},
		{
			test:            "missing key ARN",
			region:          "region_1",
			certFileARN:     "cert",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "configuration missing key ARN",
		},
		{
			test:            "missing cert ARN",
			region:          "region_1",
			keyFileARN:      "key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "configuration missing cert ARN",
		},
		{
			test:            "missing cert and key ARNs",
			region:          "region_1",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "configuration missing both cert ARN and key ARN",
		},
		{
			test:            "fails to create client",
			region:          "",
			certFileARN:     "cert",
			keyFileARN:      "key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "failed to create AWS client: an AWS region is required, but was not found",
		},
		{
			test:            "cert not found",
			region:          "region_1",
			certFileARN:     "not_found",
			keyFileARN:      "key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to read not_found: secret not found",
		},
		{
			test:            "malformed cert",
			region:          "region_1",
			certFileARN:     "invalid_cert",
			keyFileARN:      "key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.Internal,
			expectMsgPrefix: "unable to parse certificate:",
		},

		{
			test:            "key not found",
			region:          "region_1",
			certFileARN:     "cert",
			keyFileARN:      "not_found",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to read not_found: secret not found",
		},
		{
			test:            "malformed key",
			region:          "region_1",
			certFileARN:     "cert",
			keyFileARN:      "invalid_key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.Internal,
			expectMsgPrefix: "unable to parse private key:",
		},
		{
			test:            "cert and key not match",
			region:          "region_1",
			certFileARN:     "cert",
			keyFileARN:      "alternative_key",
			accessKeyID:     "access_key_id",
			secretAccessKey: "secret_access_key",
			securityToken:   "security_token",
			assumeRoleARN:   "assume_role_arn",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "certificate and private key does not match",
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
					Region:          tt.region,
					CertFileARN:     tt.certFileARN,
					KeyFileARN:      tt.keyFileARN,
					AccessKeyID:     tt.accessKeyID,
					SecretAccessKey: tt.secretAccessKey,
					SecurityToken:   tt.securityToken,
					AssumeRoleARN:   tt.assumeRoleARN,
				}))
			}

			p := new(Plugin)
			p.hooks.clock = clock.NewMock()
			p.hooks.newClient = newFakeSecretsManagerClient

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
		})
	}
}

func TestMintX509CA(t *testing.T) {
	key := testkey.NewEC256(t)
	clk := clock.NewMock()

	x509Authority, err := pemutil.LoadCertificates("testdata/keys/EC/cert.pem")
	require.NoError(t, err, "failed to load X509 Authority from disk")

	makeCSR := func(spiffeID string) []byte {
		csr, err := util.NewCSRTemplateWithKey(spiffeID, key)
		require.NoError(t, err)
		return csr
	}

	successConfiguration := &Configuration{
		Region:          "region_1",
		CertFileARN:     "cert",
		KeyFileARN:      "key",
		AccessKeyID:     "access_key_id",
		SecretAccessKey: "secret_access_key",
		SecurityToken:   "security_token",
		AssumeRoleARN:   "assume_role_arn",
	}

	for _, tt := range []struct {
		test                    string
		configuration           *Configuration
		csr                     []byte
		preferredTTL            time.Duration
		expectCode              codes.Code
		expectMsgPrefix         string
		expectX509CASpiffeID    string
		expectedX509Authorities []*x509.Certificate
		expectTTL               time.Duration
	}{
		{
			test:                    "valid CSR",
			configuration:           successConfiguration,
			csr:                     makeCSR("spiffe://example.org"),
			preferredTTL:            x509svid.DefaultUpstreamCATTL + time.Hour,
			expectTTL:               x509svid.DefaultUpstreamCATTL + time.Hour,
			expectX509CASpiffeID:    "spiffe://example.org",
			expectedX509Authorities: x509Authority,
		},
		{
			test:                    "using default ttl",
			configuration:           successConfiguration,
			csr:                     makeCSR("spiffe://example.org"),
			expectTTL:               x509svid.DefaultUpstreamCATTL,
			expectX509CASpiffeID:    "spiffe://example.org",
			expectedX509Authorities: x509Authority,
		},
		{
			test:            "configuration fail",
			csr:             makeCSR("spiffe://example.org"),
			expectCode:      codes.FailedPrecondition,
			expectMsgPrefix: "upstreamauthority(awssecret): not configured",
		},
		{
			test:            "unable to sign CSR",
			configuration:   successConfiguration,
			csr:             []byte{1},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(awssecret): unable to sign CSR: unable to parse CSR",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			p := new(Plugin)
			p.hooks.clock = clk
			p.hooks.getenv = func(s string) string {
				return ""
			}
			p.hooks.newClient = newFakeSecretsManagerClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			}

			if tt.configuration != nil {
				options = append(options, plugintest.ConfigureJSON(tt.configuration))
			}

			ua := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), ua,
				options...,
			)

			x509CA, x509Authorities, stream, err := ua.MintX509CA(context.Background(), tt.csr, tt.preferredTTL)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				assert.Nil(t, x509CA)
				assert.Nil(t, x509Authorities)
				assert.Nil(t, stream)
				return
			}

			if assert.Len(t, x509CA, 1, "only expect 1 x509CA") {
				cert := x509CA[0]
				// assert key
				isEqual, err := cryptoutil.PublicKeyEqual(cert.PublicKey, key.Public())
				if assert.NoError(t, err, "unable to determine key equality") {
					assert.True(t, isEqual, "x509CA key does not match expected key")
				}
				// assert ttl
				ttl := cert.NotAfter.Sub(clk.Now())
				assert.Equal(t, tt.expectTTL, ttl, "TTL does not match")

				// assert CA has expected SpiffeID
				assert.Equal(t, tt.expectX509CASpiffeID, cert.URIs[0].String())
			}

			require.Equal(t, tt.expectedX509Authorities, x509Authorities)

			// Plugin does not support streaming back changes so assert the
			// stream returns EOF.
			_, streamErr := stream.RecvUpstreamX509Authorities()
			assert.True(t, errors.Is(streamErr, io.EOF))
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	p := new(Plugin)
	p.hooks.clock = clock.NewMock()
	p.hooks.newClient = newFakeSecretsManagerClient

	ua := new(upstreamauthority.V1)
	plugintest.Load(t, builtin(p), ua,
		plugintest.ConfigureJSON(Configuration{
			Region:          "region_1",
			CertFileARN:     "cert",
			KeyFileARN:      "key",
			AccessKeyID:     "access_key_id",
			SecretAccessKey: "secret_access_key",
			SecurityToken:   "security_token",
			AssumeRoleARN:   "assume_role_arn",
		}),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	pkixBytes, err := x509.MarshalPKIXPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)

	jwtAuthorities, stream, err := ua.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(awssecret): publishing upstream is unsupported")
	assert.Nil(t, jwtAuthorities)
	assert.Nil(t, stream)
}
