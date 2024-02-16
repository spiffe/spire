package credtemplate_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx              = context.Background()
	now              = time.Now().Add(time.Hour).Truncate(time.Minute)
	td               = spiffeid.RequireTrustDomainFromString("domain.test")
	sn               = big.NewInt(99)
	publicKey        = testkey.MustEC256().Public()
	publicKeyID, _   = x509util.GetSubjectKeyID(publicKey)
	parentTTL        = 7 * 24 * time.Hour
	parentNotAfter   = now.Add(parentTTL)
	parentKey        = testkey.MustEC256().Public()
	parentKeyID, _   = x509util.GetSubjectKeyID(parentKey)
	parentChain      = []*x509.Certificate{{PublicKey: parentKey, SubjectKeyId: parentKeyID, NotAfter: parentNotAfter}}
	caID             = td.ID()
	notBefore        = now.Add(-10 * time.Second)
	x509CANotAfter   = now.Add(credtemplate.DefaultX509CATTL)
	x509SVIDNotAfter = now.Add(credtemplate.DefaultX509SVIDTTL)
	jwtSVIDNotAfter  = now.Add(credtemplate.DefaultJWTSVIDTTL)
	caKeyUsage       = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	svidKeyUsage     = x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature
	svidExtKeyUsage  = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	serverID         = spiffeid.RequireFromPath(td, "/spire/server")
	agentID          = spiffeid.RequireFromPath(td, "/spire/agent/foo/foo-1")
	workloadID       = spiffeid.RequireFromPath(td, "/workload")
)

func TestNewBuilderRequiresTrustDomain(t *testing.T) {
	_, err := credtemplate.NewBuilder(credtemplate.Config{})
	assert.EqualError(t, err, "trust domain must be set")
}

func TestNewBuilderSetsDefaults(t *testing.T) {
	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain: td,
	})
	require.NoError(t, err)

	config := builder.Config()

	// Assert that the Clock and NewSerialNumber are not nil and then set them
	// to nil before comparing the whole config. Checking the whole config in a
	// single equality check is more future proof but the defaults for these
	// fields are hard to compare.
	assert.NotNil(t, config.Clock)
	config.Clock = nil
	assert.NotNil(t, config.NewSerialNumber)
	config.NewSerialNumber = nil

	assert.Equal(t, credtemplate.Config{
		TrustDomain:            td,
		X509CASubject:          credtemplate.DefaultX509CASubject(),
		X509CATTL:              credtemplate.DefaultX509CATTL,
		X509SVIDSubject:        credtemplate.DefaultX509SVIDSubject(),
		X509SVIDTTL:            credtemplate.DefaultX509SVIDTTL,
		JWTSVIDTTL:             credtemplate.DefaultJWTSVIDTTL,
		JWTIssuer:              "",
		AgentSVIDTTL:           credtemplate.DefaultX509SVIDTTL,
		ExcludeSNFromCASubject: false,
	}, config)
}

func TestNewBuilderAllowsConfigOverrides(t *testing.T) {
	configIn := credtemplate.Config{
		TrustDomain:     td,
		X509CASubject:   pkix.Name{CommonName: "X509CA"},
		X509SVIDSubject: pkix.Name{CommonName: "X509SVID"},
		X509CATTL:       1 * time.Minute,
		X509SVIDTTL:     2 * time.Minute,
		JWTSVIDTTL:      3 * time.Minute,
		JWTIssuer:       "ISSUER",
		AgentSVIDTTL:    4 * time.Minute,
	}
	builder, err := credtemplate.NewBuilder(configIn)
	require.NoError(t, err)

	configOut := builder.Config()

	// Assert that the Clock and NewSerialNumber are not nil and then set them
	// to nil before comparing the whole config. Checking the whole config in a
	// single equality check is more future proof but the defaults for these
	// fields are hard to compare.
	assert.NotNil(t, configOut.Clock)
	configOut.Clock = nil
	assert.NotNil(t, configOut.NewSerialNumber)
	configOut.NewSerialNumber = nil

	assert.Equal(t, configIn, configOut)
}

func TestBuildSelfSignedX509CATemplate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.SelfSignedX509CAParams)
		overrideExpected func(expected *x509.Certificate)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.SelfSignedX509CAParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "override X509CATTL",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CATTL = time.Minute * 23
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(time.Minute * 23)
			},
		},
		{
			desc: "exclude serial number from subject",
			overrideConfig: func(config *credtemplate.Config) {
				config.ExcludeSNFromCASubject = true
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{Country: []string{"US"}, Organization: []string{"SPIFFE"}}
			},
		},
		{
			desc: "override X509CASubject",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CASubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "99"}
			},
		},
		{
			desc: "override X509CASubject including SerialNumber",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CASubject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "42"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "42"}
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.PolicyIdentifiers = []asn1.ObjectIdentifier{{1}}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.PolicyIdentifiers = []asn1.ObjectIdentifier{{1}}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.SelfSignedX509CAParams{
					PublicKey: publicKey,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildSelfSignedX509CATemplate(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.Certificate{
					SerialNumber:          sn,
					URIs:                  idURIs(caID),
					Subject:               pkix.Name{Country: []string{"US"}, SerialNumber: "99", Organization: []string{"SPIFFE"}},
					SubjectKeyId:          publicKeyID,
					BasicConstraintsValid: true,
					IsCA:                  true,
					KeyUsage:              caKeyUsage,
					NotBefore:             notBefore,
					NotAfter:              x509CANotAfter,
					PublicKey:             publicKey,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildUpstreamSignedX509CACSR(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.UpstreamSignedX509CAParams)
		overrideExpected func(expected *x509.CertificateRequest)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.UpstreamSignedX509CAParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "exclude serial number from subject",
			overrideConfig: func(config *credtemplate.Config) {
				config.ExcludeSNFromCASubject = true
			},
			overrideExpected: func(expected *x509.CertificateRequest) {
				expected.Subject = pkix.Name{Country: []string{"US"}, Organization: []string{"SPIFFE"}}
			},
		},
		{
			desc: "override X509CASubject",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CASubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.CertificateRequest) {
				expected.Subject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "99"}
			},
		},
		{
			desc: "override X509CASubject including SerialNumber",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CASubject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "42"}
			},
			overrideExpected: func(expected *x509.CertificateRequest) {
				expected.Subject = pkix.Name{CommonName: "OVERRIDE", SerialNumber: "42"}
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.CertificateRequest) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.CertificateRequest) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.UpstreamSignedX509CAParams{
					PublicKey: publicKey,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildUpstreamSignedX509CACSR(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.CertificateRequest{
					Subject:   pkix.Name{Country: []string{"US"}, SerialNumber: "99", Organization: []string{"SPIFFE"}},
					URIs:      idURIs(caID),
					PublicKey: publicKey,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildDownstreamX509CATemplate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.DownstreamX509CAParams)
		overrideExpected func(expected *x509.Certificate)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid parent chain",
			overrideParams: func(params *credtemplate.DownstreamX509CAParams) {
				params.ParentChain = nil
			},
			expectErr: "parent chain required to build downstream X509 CA template",
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.DownstreamX509CAParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "overridden X509CASubject does not apply to downstream CA",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509CASubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.Certificate) {
			},
		},
		{
			desc: "override X509SVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				// Downstream CAs have historically been signed using the default X509-SVID TTL
				config.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL * 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL * 2)
			},
		},
		{
			desc: "with ttl",
			overrideParams: func(params *credtemplate.DownstreamX509CAParams) {
				params.TTL = credtemplate.DefaultX509SVIDTTL / 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL / 2)
			},
		},
		{
			desc: "ttl gets capped",
			overrideParams: func(params *credtemplate.DownstreamX509CAParams) {
				params.TTL = parentTTL + time.Hour
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(parentTTL)
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.PolicyIdentifiers = []asn1.ObjectIdentifier{{1}}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.PolicyIdentifiers = []asn1.ObjectIdentifier{{1}}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.DownstreamX509CAParams{
					ParentChain: parentChain,
					PublicKey:   publicKey,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildDownstreamX509CATemplate(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.Certificate{
					SerialNumber:          sn,
					Subject:               pkix.Name{OrganizationalUnit: []string{"DOWNSTREAM-1"}},
					URIs:                  idURIs(caID),
					PublicKey:             publicKey,
					IsCA:                  true,
					BasicConstraintsValid: true,
					KeyUsage:              caKeyUsage,
					SubjectKeyId:          publicKeyID,
					AuthorityKeyId:        parentKeyID,
					NotBefore:             notBefore,
					// Downstream CAs have historically been signed using the default X509-SVID TTL
					NotAfter: x509SVIDNotAfter,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildServerX509SVIDTemplate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.ServerX509SVIDParams)
		overrideExpected func(expected *x509.Certificate)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid parent chain",
			overrideParams: func(params *credtemplate.ServerX509SVIDParams) {
				params.ParentChain = nil
			},
			expectErr: "parent chain required to build X509-SVID template",
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.ServerX509SVIDParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "override X509SVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL * 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL * 2)
			},
		},
		{
			desc: "ttl capped by parent chain",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDTTL = parentTTL + time.Hour
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(parentTTL)
			},
		},
		{
			desc: "override X509SVIDSubject",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDSubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{
					CommonName: "OVERRIDE",
				}
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.ServerX509SVIDParams{
					ParentChain: parentChain,
					PublicKey:   publicKey,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildServerX509SVIDTemplate(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.Certificate{
					SerialNumber: sn,
					Subject: pkix.Name{
						Country:      []string{"US"},
						Organization: []string{"SPIRE"},
					},
					SubjectKeyId:          publicKeyID,
					AuthorityKeyId:        parentKeyID,
					URIs:                  idURIs(serverID),
					PublicKey:             publicKey,
					BasicConstraintsValid: true,
					IsCA:                  false,
					KeyUsage:              svidKeyUsage,
					ExtKeyUsage:           svidExtKeyUsage,
					NotBefore:             notBefore,
					NotAfter:              x509SVIDNotAfter,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildAgentX509SVIDTemplate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.AgentX509SVIDParams)
		overrideExpected func(expected *x509.Certificate)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid parent chain",
			overrideParams: func(params *credtemplate.AgentX509SVIDParams) {
				params.ParentChain = nil
			},
			expectErr: "parent chain required to build X509-SVID template",
		},
		{
			desc: "empty SPIFFE ID",
			overrideParams: func(params *credtemplate.AgentX509SVIDParams) {
				params.SPIFFEID = spiffeid.ID{}
			},
			expectErr: "invalid X509-SVID ID: cannot be empty",
		},
		{
			desc: "SPIFFE ID from another trust domain",
			overrideParams: func(params *credtemplate.AgentX509SVIDParams) {
				params.SPIFFEID = spiffeid.RequireFromString("spiffe://otherdomain.test/spire/agent/foo/foo-1")
			},
			expectErr: `invalid X509-SVID ID: "spiffe://otherdomain.test/spire/agent/foo/foo-1" is not a member of trust domain "domain.test"`,
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.AgentX509SVIDParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		}, {
			desc: "override X509SVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL * 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL * 2)
			},
		},
		{
			desc: "override AgentX509SVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				// Set X509SVIDTTL as well just to make sure the AgentX509SVIDTTL is preferred.
				config.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL * 2
				config.AgentSVIDTTL = credtemplate.DefaultX509SVIDTTL * 3
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL * 3)
			},
		},
		{
			desc: "ttl capped by parent chain",
			overrideConfig: func(config *credtemplate.Config) {
				config.AgentSVIDTTL = parentTTL + time.Hour
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(parentTTL)
			},
		},
		{
			desc: "override X509SVIDSubject",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDSubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{
					CommonName: "OVERRIDE",
				}
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.AgentX509SVIDParams{
					ParentChain: parentChain,
					PublicKey:   publicKey,
					SPIFFEID:    agentID,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildAgentX509SVIDTemplate(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.Certificate{
					SerialNumber: sn,
					Subject: pkix.Name{
						Country:      []string{"US"},
						Organization: []string{"SPIRE"},
					},
					SubjectKeyId:          publicKeyID,
					AuthorityKeyId:        parentKeyID,
					URIs:                  idURIs(agentID),
					PublicKey:             publicKey,
					BasicConstraintsValid: true,
					IsCA:                  false,
					KeyUsage:              svidKeyUsage,
					ExtKeyUsage:           svidExtKeyUsage,
					NotBefore:             notBefore,
					NotAfter:              x509SVIDNotAfter,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildWorkloadX509SVIDTemplate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.WorkloadX509SVIDParams)
		overrideExpected func(expected *x509.Certificate)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "fail to get serial number",
			overrideConfig: func(config *credtemplate.Config) {
				config.NewSerialNumber = failNewSerialNumber
			},
			expectErr: "failed to get new serial number: oh no",
		},
		{
			desc: "invalid parent chain",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.ParentChain = nil
			},
			expectErr: "parent chain required to build X509-SVID template",
		},
		{
			desc: "empty SPIFFE ID",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.SPIFFEID = spiffeid.ID{}
			},
			expectErr: "invalid X509-SVID ID: cannot be empty",
		},
		{
			desc: "SPIFFE ID from another trust domain",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.SPIFFEID = spiffeid.RequireFromString("spiffe://otherdomain.test/spire/agent/foo/foo-1")
			},
			expectErr: `invalid X509-SVID ID: "spiffe://otherdomain.test/spire/agent/foo/foo-1" is not a member of trust domain "domain.test"`,
		},
		{
			desc: "invalid public key",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "invalid DNS names",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.PublicKey = nil
			},
			expectErr: "x509: unsupported public key type: <nil>",
		},
		{
			desc: "override X509SVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL * 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL * 2)
			},
		},
		{
			desc: "ttl capped by parent chain",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDTTL = parentTTL + time.Hour
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(parentTTL)
			},
		},
		{
			desc: "override X509SVIDSubject",
			overrideConfig: func(config *credtemplate.Config) {
				config.X509SVIDSubject = pkix.Name{CommonName: "OVERRIDE"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject = pkix.Name{
					CommonName: "OVERRIDE",
				}
			},
		},
		{
			desc: "with DNS names",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
				// CommonName is set to first DNS name by default
				expected.Subject.CommonName = "DNSNAME1"
			},
		},
		{
			desc: "with DNS names and subject",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
				params.Subject.CommonName = "COMMONNAME"
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
				// CommonName is set to first DNS name by default even when
				// Subject is explicit.
				expected.Subject = pkix.Name{
					CommonName: "DNSNAME1",
				}
			},
		},
		{
			desc: "with DNS names and subject and composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1, onlyCommonName: true}}
			},
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
				params.Subject.CommonName = "COMMONNAME"
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.DNSNames = []string{"DNSNAME1", "DNSNAME2"}
				// CommonName would normally be set to first DNS name by
				// default even when Subject is explicit but the composer is
				// allowed to override.
				expected.Subject = pkix.Name{
					CommonName: "OVERRIDE-1",
				}
			},
		},

		{
			desc: "with ttl",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.TTL = credtemplate.DefaultX509SVIDTTL / 2
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(credtemplate.DefaultX509SVIDTTL / 2)
			},
		},
		{
			desc: "ttl gets capped",
			overrideParams: func(params *credtemplate.WorkloadX509SVIDParams) {
				params.TTL = parentTTL + time.Hour
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.NotAfter = now.Add(parentTTL)
			},
		},
		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-1"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyCommonName: true}}
			},
			overrideExpected: func(expected *x509.Certificate) {
				expected.Subject.CommonName = "OVERRIDE-2"
				expected.DNSNames = []string{"OVERRIDE-1"}
				expected.ExtraExtensions = []pkix.Extension{{Id: makeOID(1), Value: []byte{1}}}
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.WorkloadX509SVIDParams{
					ParentChain: parentChain,
					PublicKey:   publicKey,
					SPIFFEID:    workloadID,
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildWorkloadX509SVIDTemplate(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := &x509.Certificate{
					SerialNumber: sn,
					Subject: pkix.Name{
						Country:      []string{"US"},
						Organization: []string{"SPIRE"},
					},
					SubjectKeyId:          publicKeyID,
					AuthorityKeyId:        parentKeyID,
					URIs:                  idURIs(workloadID),
					PublicKey:             publicKey,
					BasicConstraintsValid: true,
					IsCA:                  false,
					KeyUsage:              svidKeyUsage,
					ExtKeyUsage:           svidExtKeyUsage,
					NotBefore:             notBefore,
					NotAfter:              x509SVIDNotAfter,
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func TestBuildWorkloadJWTSVIDClaims(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		overrideConfig   func(config *credtemplate.Config)
		overrideParams   func(params *credtemplate.WorkloadJWTSVIDParams)
		overrideExpected func(expected map[string]any)
		expectErr        string
	}{
		{
			desc: "defaults",
		},
		{
			desc: "empty SPIFFE ID",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.SPIFFEID = spiffeid.ID{}
			},
			expectErr: "invalid JWT-SVID ID: cannot be empty",
		},
		{
			desc: "SPIFFE ID from another trust domain",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.SPIFFEID = spiffeid.RequireFromString("spiffe://otherdomain.test/spire/agent/foo/foo-1")
			},
			expectErr: `invalid JWT-SVID ID: "spiffe://otherdomain.test/spire/agent/foo/foo-1" is not a member of trust domain "domain.test"`,
		},
		{
			desc: "empty audience",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.Audience = nil
			},
			expectErr: "invalid JWT-SVID audience: cannot be empty",
		},
		{
			desc: "empty audience value",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.Audience = []string{""}
			},
			expectErr: "invalid JWT-SVID audience: cannot be empty",
		},
		{
			desc: "empty audience value otherwise ignored",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.Audience = []string{"", "AUDIENCE"}
			},
		},
		{
			desc: "multiple audience value",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.Audience = []string{"AUDIENCE1", "AUDIENCE2"}
			},
			overrideExpected: func(expected map[string]any) {
				expected["aud"] = []string{"AUDIENCE1", "AUDIENCE2"}
			},
		},
		{
			desc: "override JWTSVIDTTL",
			overrideConfig: func(config *credtemplate.Config) {
				config.JWTSVIDTTL = credtemplate.DefaultJWTSVIDTTL * 2
			},
			overrideExpected: func(expected map[string]any) {
				expected["exp"] = jwt.NewNumericDate(now.Add(credtemplate.DefaultJWTSVIDTTL * 2))
			},
		},
		{
			desc: "ttl capped by expiration cap",
			overrideConfig: func(config *credtemplate.Config) {
				config.JWTSVIDTTL = parentTTL + time.Hour
			},
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.ExpirationCap = now.Add(parentTTL)
			},
			overrideExpected: func(expected map[string]any) {
				expected["exp"] = jwt.NewNumericDate(now.Add(parentTTL))
			},
		},
		{
			desc: "with ttl",
			overrideParams: func(params *credtemplate.WorkloadJWTSVIDParams) {
				params.TTL = credtemplate.DefaultJWTSVIDTTL / 2
			},
			overrideExpected: func(expected map[string]any) {
				expected["exp"] = jwt.NewNumericDate(now.Add(credtemplate.DefaultJWTSVIDTTL / 2))
			},
		},
		{
			desc: "with issuer",
			overrideConfig: func(config *credtemplate.Config) {
				config.JWTIssuer = "ISSUER"
			},
			overrideExpected: func(expected map[string]any) {
				expected["iss"] = "ISSUER"
			},
		},

		{
			desc: "single composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}}
			},
			overrideExpected: func(expected map[string]any) {
				expected["foo"] = "VALUE-1"
				expected["bar"] = "VALUE-1"
			},
		},
		{
			desc: "two composers",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{fakeCC{id: 1}, fakeCC{id: 2, onlyFoo: true}}
			},
			overrideExpected: func(expected map[string]any) {
				expected["foo"] = "VALUE-2"
				expected["bar"] = "VALUE-1"
			},
		},
		{
			desc: "composer fails",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{badCC{}}
			},
			expectErr: "oh no",
		},
		{
			desc: "real no-op composer",
			overrideConfig: func(config *credtemplate.Config) {
				config.CredentialComposers = []credentialcomposer.CredentialComposer{loadNoopV1Plugin(t)}
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			testBuilder(t, tc.overrideConfig, func(t *testing.T, credBuilder *credtemplate.Builder) {
				params := credtemplate.WorkloadJWTSVIDParams{
					SPIFFEID: workloadID,
					Audience: []string{"AUDIENCE"},
				}
				if tc.overrideParams != nil {
					tc.overrideParams(&params)
				}
				template, err := credBuilder.BuildWorkloadJWTSVIDClaims(ctx, params)
				if tc.expectErr != "" {
					require.EqualError(t, err, tc.expectErr)
					return
				}
				require.NoError(t, err)

				expected := map[string]any{
					"aud": []string{"AUDIENCE"},
					"iat": jwt.NewNumericDate(now),
					"exp": jwt.NewNumericDate(jwtSVIDNotAfter),
					"sub": workloadID.String(),
				}
				if tc.overrideExpected != nil {
					tc.overrideExpected(expected)
				}
				require.Equal(t, expected, template)
			})
		})
	}
}

func testBuilder(t *testing.T, overrideConfig func(config *credtemplate.Config), fn func(*testing.T, *credtemplate.Builder)) {
	config := credtemplate.Config{
		TrustDomain:     td,
		Clock:           clock.NewMockAt(t, now),
		NewSerialNumber: func() (*big.Int, error) { return sn, nil },
	}
	if overrideConfig != nil {
		overrideConfig(&config)
	}
	credBuilder, err := credtemplate.NewBuilder(config)
	require.NoError(t, err)
	fn(t, credBuilder)
}

func failNewSerialNumber() (*big.Int, error) { return nil, errors.New("oh no") }

type badCC struct {
	catalog.PluginInfo
}

func (badCC) ComposeServerX509CA(context.Context, credentialcomposer.X509CAAttributes) (credentialcomposer.X509CAAttributes, error) {
	return credentialcomposer.X509CAAttributes{}, errors.New("oh no")
}

func (badCC) ComposeServerX509SVID(context.Context, credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return credentialcomposer.X509SVIDAttributes{}, errors.New("oh no")
}

func (badCC) ComposeAgentX509SVID(context.Context, spiffeid.ID, crypto.PublicKey, credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return credentialcomposer.X509SVIDAttributes{}, errors.New("oh no")
}

func (badCC) ComposeWorkloadX509SVID(context.Context, spiffeid.ID, crypto.PublicKey, credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return credentialcomposer.X509SVIDAttributes{}, errors.New("oh no")
}

func (badCC) ComposeWorkloadJWTSVID(context.Context, spiffeid.ID, credentialcomposer.JWTSVIDAttributes) (credentialcomposer.JWTSVIDAttributes, error) {
	return credentialcomposer.JWTSVIDAttributes{}, errors.New("oh no")
}

type fakeCC struct {
	catalog.PluginInfo

	id             byte
	onlyCommonName bool
	onlyFoo        bool
}

func (cc fakeCC) ComposeServerX509CA(_ context.Context, attributes credentialcomposer.X509CAAttributes) (credentialcomposer.X509CAAttributes, error) {
	attributes.Subject.CommonName = cc.applySuffix("OVERRIDE")
	if !cc.onlyCommonName {
		attributes.PolicyIdentifiers = []asn1.ObjectIdentifier{makeOID(cc.id)}
		attributes.ExtraExtensions = []pkix.Extension{{Id: makeOID(cc.id), Value: []byte{cc.id}}}
	}
	return attributes, nil
}

func (cc fakeCC) ComposeServerX509SVID(_ context.Context, attributes credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return cc.overrideX509SVIDAttributes(attributes), nil
}

func (cc fakeCC) ComposeAgentX509SVID(_ context.Context, _ spiffeid.ID, _ crypto.PublicKey, attributes credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return cc.overrideX509SVIDAttributes(attributes), nil
}

func (cc fakeCC) ComposeWorkloadX509SVID(_ context.Context, _ spiffeid.ID, _ crypto.PublicKey, attributes credentialcomposer.X509SVIDAttributes) (credentialcomposer.X509SVIDAttributes, error) {
	return cc.overrideX509SVIDAttributes(attributes), nil
}

func (cc fakeCC) ComposeWorkloadJWTSVID(_ context.Context, _ spiffeid.ID, attributes credentialcomposer.JWTSVIDAttributes) (credentialcomposer.JWTSVIDAttributes, error) {
	attributes.Claims["foo"] = cc.applySuffix("VALUE")
	if !cc.onlyFoo {
		attributes.Claims["bar"] = cc.applySuffix("VALUE")
	}
	return attributes, nil
}

func (cc fakeCC) overrideX509SVIDAttributes(attributes credentialcomposer.X509SVIDAttributes) credentialcomposer.X509SVIDAttributes {
	attributes.Subject.CommonName = cc.applySuffix("OVERRIDE")
	if !cc.onlyCommonName {
		attributes.DNSNames = []string{cc.applySuffix("OVERRIDE")}
		attributes.ExtraExtensions = []pkix.Extension{{Id: makeOID(cc.id), Value: []byte{cc.id}}}
	}
	return attributes
}

func (cc fakeCC) applySuffix(s string) string {
	return fmt.Sprintf("%s-%d", s, cc.id)
}

func makeOID(id byte) []int {
	return []int{int(id)}
}

func idURIs(id spiffeid.ID) []*url.URL {
	return []*url.URL{id.URL()}
}

func loadNoopV1Plugin(t *testing.T) credentialcomposer.CredentialComposer {
	server := credentialcomposerv1.CredentialComposerPluginServer(credentialcomposerv1.UnimplementedCredentialComposerServer{})
	cc := new(credentialcomposer.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("noop", server), cc)
	return cc
}
