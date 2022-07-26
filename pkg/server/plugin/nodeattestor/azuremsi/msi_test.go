package azuremsi

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// Azure MSI tokens are RSA signed
	keyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAKC4t/KjGW7qAuK89ZQGasYlI1octSwElSGioJag1w7s/d2EXjtY
4FDYOYa8bKB3wC6rIzPDKUR783fZ3gJmvdI8TLlnj25wyPApVkRXC3ZQxYj5/hcG
aQuNWr6zrY8C8QIDAQABAmB95nViQtWHhxTfnPobDLPTp//7dQWPB7/y6zw1AqW0
8X0ka66Net+tNNRLcYr+YQ8Sv4suvGVo3NXBNU+jJVys2s+kB2vvfh5w/mpaEyM1
C3UGsX8WWcRvxkxQhwR5VmECMQDWAufI9k7mfo8kjPcFcxKZbwiklTn0p6IVNXIf
cA7f210xizyPm2NDUvs1v+f6Yw0CMQDAQT1zR4qlTm4tufG0+IlfPaP9FxvTl+ox
dxnOm4DzNx14+seX6Mont4ucrrFnNnUCMQC3u8zVGqnId3VbMu7MreuU8N+htUAJ
jHW58aWl2eXbSJCs/VYkEIra/P4ROk3mCG0CMQC3mpaRDXW/QRO/36CR7/lhV4DR
J8yPWrlx3AhtY9zWaYBgFT+gN9U38PYIAF2z8DECMHNJ/MNm0Keasv9K3sfrCpL6
bpR/VgtruOOSiOvJJ9xOAKCSsyeVpZdHrWlY7fkCKg==
-----END RSA PRIVATE KEY-----`)
)

const (
	testKeyID = "KEYID"

	resourceID = "https://example.org/app/"
)

func TestMSIAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(MSIAttestorSuite))
}

type MSIAttestorSuite struct {
	spiretest.Suite

	attestor   nodeattestor.NodeAttestor
	key        *rsa.PrivateKey
	jwks       *jose.JSONWebKeySet
	now        time.Time
	agentStore *fakeagentstore.AgentStore
}

func (s *MSIAttestorSuite) SetupTest() {
	// load up the signer used for JWT signing
	var err error
	s.key, err = pemutil.ParseRSAPrivateKey(keyPEM)
	s.Require().NoError(err)
	s.jwks = new(jose.JSONWebKeySet)
	s.now = time.Now()
	s.agentStore = fakeagentstore.New()

	s.attestor = s.loadPlugin()
}

func (s *MSIAttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor
	s.requireAttestError(s.T(), []byte("payload"), codes.FailedPrecondition, "nodeattestor(azure_msi): not configured")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoAttestationDataPayload() {
	s.requireAttestError(s.T(), nil, codes.InvalidArgument, "payload cannot be empty")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedAttestationDataPayload() {
	s.requireAttestError(s.T(), []byte("{"), codes.InvalidArgument, "nodeattestor(azure_msi): failed to unmarshal data payload")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoToken() {
	s.requireAttestError(s.T(), makeAttestPayload(""),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): missing token from attestation data")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedToken() {
	s.requireAttestError(s.T(), makeAttestPayload("blah"),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): unable to parse token")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDMissing() {
	s.requireAttestError(s.T(), s.signAttestPayload("", "", "", ""),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): token missing key id")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDNotFound() {
	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", "", "", ""),
		codes.InvalidArgument,
		`nodeattestor(azure_msi): key id "KEYID" not found`)
}

func (s *MSIAttestorSuite) TestAttestFailsWithBadSignature() {
	s.addKey()

	// sign a token and replace the signature
	token := s.signToken("KEYID", "", "", "")
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3)
	parts[2] = "aaaa"
	token = strings.Join(parts, ".")

	s.requireAttestError(s.T(), makeAttestPayload(token),
		codes.InvalidArgument,
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsWithAlgorithmMismatch() {
	s.addKey()

	// sign a token with a different key algorithm than that of the key in
	// the key set.
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("0123456789ABCDEF"),
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "KEYID",
		},
	})
	s.Require().NoError(err)

	token, err := jwt.Signed(signer).CompactSerialize()
	s.Require().NoError(err)

	s.requireAttestError(s.T(), makeAttestPayload(token),
		codes.InvalidArgument,
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsClaimValidation() {
	s.addKey()

	s.T().Run("missing tenant id claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): token missing tenant ID claim")
	})

	s.T().Run("unauthorized tenant id claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "BADTENANTID", "PRINCIPALID"),
			codes.PermissionDenied,
			`nodeattestor(azure_msi): tenant "BADTENANTID" is not authorized`)
	})

	s.T().Run("no audience", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", "", "TENANTID", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): unable to validate token claims: square/go-jose/jwt: validation failed, invalid audience claim (aud)")
	})

	s.T().Run("wrong audience", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", "FOO", "TENANTID", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): unable to validate token claims: square/go-jose/jwt: validation failed, invalid audience claim (aud)")
	})

	s.T().Run(" missing principal id (sub) claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "TENANTID", ""),
			codes.Internal,
			"nodeattestor(azure_msi): token missing subject claim")
	})
}

func (s *MSIAttestorSuite) TestAttestTokenExpiration() {
	s.addKey()
	token := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")

	// within 5m leeway (token expires at 1m + 5m leeway = 6m)
	s.adjustTime(6 * time.Minute)
	_, err := s.attestor.Attest(context.Background(), token, expectNoChallenge)
	s.Require().NotNil(err)

	// just after 5m leeway
	s.adjustTime(time.Second)
	s.requireAttestError(s.T(), token, codes.Internal, "nodeattestor(azure_msi): unable to validate token claims: square/go-jose/jwt: validation failed, token is expired (exp)")
}

func (s *MSIAttestorSuite) TestAttestSuccess() {
	s.addKey()

	s.T().Run("Success against TENANTID, which uses the custom resource ID", func(t *testing.T) {
		payload := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")
		resp, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, resp.AgentID, "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID")
	})

	s.T().Run("Success against TENANTID2, which uses the default resource ID", func(t *testing.T) {
		payload := s.signAttestPayload("KEYID", azure.DefaultMSIResourceID, "TENANTID2", "PRINCIPALID")
		resp, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, resp.AgentID, "spiffe://example.org/spire/agent/azure_msi/TENANTID2/PRINCIPALID")
	})
}

func (s *MSIAttestorSuite) TestAttestFailsWhenAttestedBefore() {
	s.addKey()

	agentID := "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID"
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})
	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		codes.PermissionDenied,
		"nodeattestor(azure_msi): attestation data has already been used to attest an agent")
}

func (s *MSIAttestorSuite) TestConfigure() {
	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed configuration", func(t *testing.T) {
		err := doConfig(t, coreConfig, "blah")
		spiretest.RequireErrorContains(t, err, "unable to decode configuration")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, "")
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "core configuration missing trust domain")
	})

	s.T().Run("missing tenants", func(t *testing.T) {
		err := doConfig(t, coreConfig, "")
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration must have at least one tenant")
	})

	s.T().Run("success", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
			"TENANTID2" = {}
		}
		`)
		require.NoError(t, err)
	})
}

func (s *MSIAttestorSuite) adjustTime(d time.Duration) {
	s.now = s.now.Add(d)
}

func (s *MSIAttestorSuite) newSigner(keyID string) jose.Signer {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   s.key,
			KeyID: keyID,
		},
	}, nil)
	s.Require().NoError(err)
	return signer
}

func (s *MSIAttestorSuite) signToken(keyID, audience, tenantID, principalID string) string {
	builder := jwt.Signed(s.newSigner(keyID))

	// build up standard claims
	claims := jwt.Claims{
		Subject:   principalID,
		NotBefore: jwt.NewNumericDate(s.now),
		Expiry:    jwt.NewNumericDate(s.now.Add(time.Minute)),
	}
	if audience != "" {
		claims.Audience = []string{audience}
	}
	builder = builder.Claims(claims)

	// add the tenant id claim
	if tenantID != "" {
		builder = builder.Claims(map[string]interface{}{
			"tid": tenantID,
		})
	}

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *MSIAttestorSuite) signAttestPayload(keyID, audience, tenantID, principalID string) []byte {
	return makeAttestPayload(s.signToken(keyID, audience, tenantID, principalID))
}

func (s *MSIAttestorSuite) addKey() {
	s.jwks.Keys = append(s.jwks.Keys, jose.JSONWebKey{
		Key:   s.key.Public(),
		KeyID: testKeyID,
	})
}

func (s *MSIAttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	attestor := New()
	attestor.hooks.now = func() time.Time {
		return s.now
	}
	attestor.hooks.keySetProvider = jwtutil.KeySetProviderFunc(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
		return s.jwks, nil
	})

	v1 := new(nodeattestor.V1)

	plugintest.Load(s.T(), builtin(attestor), v1,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
			"TENANTID2" = {}
		}
	`))
	return v1
}

func (s *MSIAttestorSuite) requireAttestError(t *testing.T, payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMsg)
	require.Nil(t, result)
}

func makeAttestPayload(token string) []byte {
	return []byte(fmt.Sprintf(`{"token": %q}`, token))
}

func expectNoChallenge(ctx context.Context, challenge []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
