package k8ssat

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	authv1 "k8s.io/api/authentication/v1"
)

var (
	fooKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMB4gbT09H2RKXaxbu6IV9C3WY+pvkGAbrlQRIHLHwV3Xt1HchjX
c08v1VEoTBN2YTjhZJlDb/VUsNMJsmBFBBted5geRcbrDtXFlUJ8tQoQx1dWM4Aa
xcdULJ83A9ICKwIDAQABAmBR1asInrIphYQEtHJ/NzdnRd3tqHV9cjch0dAfA5dA
Ar4yBYOsrkaX37WqWSDnkYgN4FWYBWn7WxeotCtA5UQ3SM5hLld67rUqAm2dLrs1
z8va6SwLzrPTu2+rmRgovFECMQDpbfPBRex7FY/xWu1pYv6X9XZ26SrC2Wc6RIpO
38AhKGjTFEMAPJQlud4e2+4I3KkCMQDTFLUvBSXokw2NvcNiM9Kqo5zCnCIkgc+C
hM3EzSh2jh4gZvRzPOhXYvNKgLx8+LMCMQDL4meXlpV45Fp3eu4GsJqi65jvP7VD
v1P0hs0vGyvbSkpUo0vqNv9G/FNQLNR6FRECMFXEMz5wxA91OOuf8HTFg9Lr+fUl
RcY5rJxm48kUZ12Mr3cQ/kCYvftL7HkYR/4rewIxANdritlIPu4VziaEhYZg7dvz
pG3eEhiqPxE++QHpwU78O+F1GznOPBvpZOB3GfyjNQ==
-----END RSA PRIVATE KEY-----`)
	barKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOIAksqKX+ByhLcme
T7MXn5Qz58BJCSvvAyRoz7+7jXGhRANCAATUWB+7Xo/JyFuh1KQ6umUbihP+AGzy
da0ItHUJ/C5HElB5cSuyOAXDQbM5fuxJIefEVpodjqsQP6D0D8CPLJ5H
-----END PRIVATE KEY-----`)
	bazKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpHVYFq6Z/LgGIG/X
+i+PWZEFjGVEUpjrMzlz95tDl4yhRANCAAQAc/I3bBO9XhgTTbLBuNA6XJBSvds9
c4gThKYxugN3V398Eieoo2HTO2L7BBjTp5yh+EUtHQD52bFseBCnZT3d
-----END PRIVATE KEY-----`)
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir             string
	fooKey          *rsa.PrivateKey
	fooSigner       jose.Signer
	barKey          *ecdsa.PrivateKey
	barSigner       jose.Signer
	bazSigner       jose.Signer
	attestor        nodeattestor.NodeAttestor
	agentStore      *fakeagentstore.AgentStore
	now             time.Time
	apiServerClient *fakeAPIServerClient
}

func (s *AttestorSuite) SetupSuite() {
	var err error
	s.fooKey, err = pemutil.ParseRSAPrivateKey(fooKeyPEM)
	s.Require().NoError(err)
	s.fooSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       s.fooKey,
	}, nil)
	s.Require().NoError(err)

	s.barKey, err = pemutil.ParseECPrivateKey(barKeyPEM)
	s.Require().NoError(err)
	s.barSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       s.barKey,
	}, nil)
	s.Require().NoError(err)

	bazKey, err := pemutil.ParseECPrivateKey(bazKeyPEM)
	s.Require().NoError(err)
	s.bazSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       bazKey,
	}, nil)
	s.Require().NoError(err)

	s.dir = s.TempDir()

	// generate a self-signed certificate for signing tokens
	s.Require().NoError(createAndWriteSelfSignedCert("FOO", s.fooKey, s.fooCertPath()))
	s.Require().NoError(createAndWriteSelfSignedCert("BAR", s.barKey, s.barCertPath()))
}

func (s *AttestorSuite) SetupTest() {
	s.agentStore = fakeagentstore.New()
	s.attestor = s.loadPlugin()
	s.now = time.Now()
}

func (s *AttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor
	s.requireAttestError([]byte("payload"), codes.FailedPrecondition, "nodeattestor(k8s_sat): not configured")
}

func (s *AttestorSuite) TestAttestFailsWhenAttestedBefore() {
	agentID := "spiffe://example.org/spire/agent/k8s_sat/FOO/UUID"
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})

	token := s.signToken(s.fooSigner, "NS1", "SA1")
	s.requireAttestError(makePayload("FOO", token),
		codes.PermissionDenied,
		"nodeattestor(k8s_sat): attestation data has already been used to attest an agent")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedPayload() {
	s.requireAttestError([]byte("{"),
		codes.InvalidArgument,
		"nodeattestor(k8s_sat): failed to unmarshal attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithNoClusterInPayload() {
	s.requireAttestError(makePayload("", "TOKEN"),
		codes.InvalidArgument,
		"nodeattestor(k8s_sat): missing cluster in attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithNoTokenInPayload() {
	s.requireAttestError(makePayload("FOO", ""),
		codes.InvalidArgument,
		"nodeattestor(k8s_sat): missing token in attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedTokenInPayload() {
	s.requireAttestError(makePayload("FOO", "blah"),
		codes.InvalidArgument,
		"nodeattestor(k8s_sat): unable to parse token")
}

func (s *AttestorSuite) TestAttestFailsIfClusterNotConfigured() {
	s.requireAttestError(makePayload("CLUSTER", "blah"),
		codes.InvalidArgument,
		`nodeattestor(k8s_sat): not configured for cluster "CLUSTER"`)
}

func (s *AttestorSuite) TestAttestFailsWithBadSignature() {
	// sign a token and replace the signature
	token := s.signToken(s.fooSigner, "", "")
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3)
	parts[2] = "aaaa"
	token = strings.Join(parts, ".")

	s.requireAttestError(makePayload("FOO", token),
		codes.InvalidArgument,
		"unable to verify token")
}

func (s *AttestorSuite) TestAttestFailsIfTokenReviewAPIFails() {
	token := s.signToken(s.barSigner, "NS2", "SA2")
	s.requireAttestError(makePayload("BAR", token),
		codes.Internal,
		"unable to validate token with TokenReview API")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedToken() {
	claims := sat_common.SATClaims{}
	claims.Namespace = "ns1"
	claims.K8s.Namespace = "ns2"

	builder := jwt.Signed(s.fooSigner)
	builder = builder.Claims(claims)
	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "malformed token: namespace found in two claims")

	// Clear the namespace from the SAT space but leave the duplicated service account name
	claims.K8s.Namespace = ""
	claims.ServiceAccountName = "sa1"
	claims.K8s.ServiceAccount.Name = "sa2"

	builder = builder.Claims(claims)
	token, err = builder.CompactSerialize()
	s.Require().NoError(err)
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "malformed token: service account name found in two claims")
}

func (s *AttestorSuite) TestAttestFailsIfTokenNotAuthenticated() {
	token := s.signToken(s.barSigner, "NS2", "SA2")
	status := createTokenStatus("NS2", "SA2", false)
	s.apiServerClient.SetTokenStatus(token, status)
	s.requireAttestError(makePayload("BAR", token), codes.PermissionDenied, "token not authenticated")
}

func (s *AttestorSuite) TestAttestFailsWithMissingNamespaceClaim() {
	token := s.signToken(s.fooSigner, "", "")
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "token missing namespace claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingNamespaceFromTokenStatus() {
	token := s.signToken(s.barSigner, "", "SA2")
	status := createTokenStatus("", "SA2", true)
	s.apiServerClient.SetTokenStatus(token, status)
	s.requireAttestError(makePayload("BAR", token), codes.Internal, "fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameClaim() {
	token := s.signToken(s.fooSigner, "NAMESPACE", "")
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "token missing service account name claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameFromTokenStatus() {
	token := s.signToken(s.barSigner, "NS2", "")
	status := createTokenStatus("NS2", "", true)
	s.apiServerClient.SetTokenStatus(token, status)
	s.requireAttestError(makePayload("BAR", token), codes.Internal, "fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotAllowListedFromTokenClaim() {
	token := s.signToken(s.fooSigner, "NS1", "NO-WHITHELISTED-SA")
	s.requireAttestError(makePayload("FOO", token), codes.PermissionDenied, `"NS1:NO-WHITHELISTED-SA" is not an allowed service account`)
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotAllowListedFromTokenStatus() {
	token := s.signToken(s.barSigner, "NS2", "NO-WHITHELISTED-SA")
	status := createTokenStatus("NS2", "NO-WHITHELISTED-SA", true)
	s.apiServerClient.SetTokenStatus(token, status)
	s.requireAttestError(makePayload("BAR", token), codes.PermissionDenied, `"NS2:NO-WHITHELISTED-SA" is not an allowed service account`)
}

func (s *AttestorSuite) TestAttestFailsIfTokenSignatureCannotBeVerifiedByCluster() {
	token := s.signToken(s.bazSigner, "NAMESPACE", "SERVICEACCOUNTNAME")
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "nodeattestor(k8s_sat): unable to verify token")
}

func (s *AttestorSuite) TestAttestSuccess() {
	// Success with FOO signed token (local validation)
	token := s.signToken(s.fooSigner, "NS1", "SA1")
	result, err := s.attestor.Attest(context.Background(), makePayload("FOO", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_sat/FOO/UUID")
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_sat", Value: "cluster:FOO"},
		{Type: "k8s_sat", Value: "agent_ns:NS1"},
		{Type: "k8s_sat", Value: "agent_sa:SA1"},
	}, result.Selectors)

	// Success with BAR signed token (token review API validation)
	token = s.signToken(s.barSigner, "NS2", "SA2")
	status := createTokenStatus("NS2", "SA2", true)
	s.apiServerClient.SetTokenStatus(token, status)
	result, err = s.attestor.Attest(context.Background(), makePayload("BAR", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_sat/BAR/UUID")
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_sat", Value: "cluster:BAR"},
		{Type: "k8s_sat", Value: "agent_ns:NS2"},
		{Type: "k8s_sat", Value: "agent_sa:SA2"},
	}, result.Selectors)
}

func (s *AttestorSuite) TestConfigure() {
	doConfig := func(coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(s.T(), BuiltIn(), nil,
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

	// malformed configuration
	err := doConfig(coreConfig, "blah")
	s.RequireErrorContains(err, "unable to decode configuration")

	// missing trust domain
	err = doConfig(catalog.CoreConfig{}, "")
	s.RequireGRPCStatus(err, codes.InvalidArgument, "core configuration missing trust domain")

	// missing clusters
	err = doConfig(coreConfig, "")
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration must have at least one cluster")

	// cluster missing service account key file
	err = doConfig(coreConfig, `clusters = {
		"FOO" = {}
	}`)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `cluster "FOO" configuration missing service account key file`)

	// cluster missing service account allow list (local validation config)
	err = doConfig(coreConfig, fmt.Sprintf(`clusters = {
		"FOO" = {
			service_account_key_file = %q
		}
	}`, s.fooCertPath()))
	s.RequireGRPCStatus(err, codes.InvalidArgument, `cluster "FOO" configuration must have at least one service account allowed`)

	// cluster missing service account allow list (token review validation config)
	err = doConfig(coreConfig, `clusters = {
		"BAR" = {
			use_token_review_api_validation = true
		}
	}`)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `cluster "BAR" configuration must have at least one service account allowed`)

	// unable to load cluster service account keys
	err = doConfig(coreConfig, fmt.Sprintf(`clusters = {
		"FOO" = {
			service_account_key_file = %q
			service_account_allow_list = ["A"]
		}
	}`, filepath.Join(s.dir, "missing.pem")))
	s.RequireErrorContains(err, `failed to load cluster "FOO" service account keys`)

	// no keys in PEM file
	s.Require().NoError(os.WriteFile(filepath.Join(s.dir, "nokeys.pem"), []byte{}, 0600))
	err = doConfig(coreConfig, fmt.Sprintf(`clusters = {
		"FOO" = {
			service_account_key_file = %q
			service_account_allow_list = ["A"]
		}
	}`, filepath.Join(s.dir, "nokeys.pem")))
	s.RequireErrorContains(err, `cluster "FOO" has no service account keys in`)
}

func (s *AttestorSuite) TestServiceAccountKeyFileAlternateEncodings() {
	fooPKCS1KeyPath := filepath.Join(s.dir, "foo-pkcs1.pem")
	fooPKCS1Bytes := x509.MarshalPKCS1PublicKey(&s.fooKey.PublicKey)
	s.Require().NoError(os.WriteFile(fooPKCS1KeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: fooPKCS1Bytes,
	}), 0600))

	fooPKIXKeyPath := filepath.Join(s.dir, "foo-pkix.pem")
	fooPKIXBytes, err := x509.MarshalPKIXPublicKey(s.fooKey.Public())
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(fooPKIXKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: fooPKIXBytes,
	}), 0600))

	barPKIXKeyPath := filepath.Join(s.dir, "bar-pkix.pem")
	barPKIXBytes, err := x509.MarshalPKIXPublicKey(s.barKey.Public())
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(barPKIXKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: barPKIXBytes,
	}), 0600))

	plugintest.Load(s.T(), BuiltIn(), nil,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configuref(`clusters = {
			"FOO-PKCS1" = {
				service_account_key_file = %q
				service_account_allow_list = ["A"]
			}
			"FOO-PKIX" = {
				service_account_key_file = %q
				service_account_allow_list = ["A"]
			}
			"BAR-PKIX" = {
				service_account_key_file = %q
				service_account_allow_list = ["A"]
			}
		}`, fooPKCS1KeyPath, fooPKIXKeyPath, barPKIXKeyPath),
	)
}

func (s *AttestorSuite) TestAttestTokenExpiration() {
	token := s.signTokenWithExpiry(s.fooSigner, "NS1", "SA1")

	// within 5m leeway (token expires at 1m + 5m leeway = 6m)
	s.adjustTime(4 * time.Minute)
	result, err := s.attestor.Attest(context.Background(), makePayload("FOO", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	// after 5m leeway
	s.adjustTime(3 * time.Minute)
	s.requireAttestError(makePayload("FOO", token), codes.InvalidArgument, "token is expired (exp)")
}

func (s *AttestorSuite) signToken(signer jose.Signer, namespace, serviceAccountName string) string {
	builder := s.createBuilder(signer, namespace, serviceAccountName, jwt.NewNumericDate(time.Time{}))

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *AttestorSuite) signTokenWithExpiry(signer jose.Signer, namespace, serviceAccountName string) string {
	builder := s.createBuilder(signer, namespace, serviceAccountName, jwt.NewNumericDate(s.now.Add(time.Minute)))

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *AttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	attestor := New()
	attestor.hooks.newUUID = func() (string, error) {
		return "UUID", nil
	}
	attestor.hooks.now = func() time.Time {
		return s.now
	}
	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configuref(`
		clusters = {
			"FOO" = {
				service_account_key_file = %q
				service_account_allow_list = ["NS1:SA1"]
			}
			"BAR" = {
				use_token_review_api_validation = true
				service_account_allow_list = ["NS2:SA2"]
			}
		}
		`, s.fooCertPath()),
	)

	// TODO: provide this client in a cleaner way
	s.apiServerClient = newFakeAPIServerClient()
	attestor.config.clusters["FOO"].client = s.apiServerClient
	attestor.config.clusters["BAR"].client = s.apiServerClient
	return v1
}

func (s *AttestorSuite) requireAttestError(payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.RequireGRPCStatusContains(err, expectCode, expectMsg)
	s.Require().Nil(result)
}

func (s *AttestorSuite) fooCertPath() string {
	return filepath.Join(s.dir, "foo.pem")
}

func (s *AttestorSuite) barCertPath() string {
	return filepath.Join(s.dir, "bar.pem")
}

func (s *AttestorSuite) adjustTime(d time.Duration) {
	s.now = s.now.Add(d)
}

func (s *AttestorSuite) createBuilder(signer jose.Signer, namespace, serviceAccountName string, numericDate *jwt.NumericDate) jwt.Builder {
	claims := sat_common.SATClaims{}
	claims.Namespace = namespace
	claims.ServiceAccountName = serviceAccountName
	claims.Expiry = numericDate

	builder := jwt.Signed(signer)
	builder = builder.Claims(claims)
	return builder
}

func makePayload(cluster, token string) []byte {
	return []byte(fmt.Sprintf(`{"cluster": %q, "token": %q}`, cluster, token))
}

func createAndWriteSelfSignedCert(cn string, signer crypto.Signer, path string) error {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     now.Add(time.Hour),
		NotBefore:    now,
		Subject:      pkix.Name{CommonName: cn},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600)
}

func createTokenStatus(namespace, serviceAccountName string, authenticated bool) *authv1.TokenReviewStatus {
	return &authv1.TokenReviewStatus{
		Authenticated: authenticated,
		User: authv1.UserInfo{
			Username: fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccountName),
		},
	}
}

func expectNoChallenge(ctx context.Context, challenge []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}

type fakeAPIServerClient struct {
	status map[string]*authv1.TokenReviewStatus
}

func newFakeAPIServerClient() *fakeAPIServerClient {
	return &fakeAPIServerClient{
		status: make(map[string]*authv1.TokenReviewStatus),
	}
}

func (c *fakeAPIServerClient) SetTokenStatus(token string, status *authv1.TokenReviewStatus) {
	c.status[token] = status
}

func (c *fakeAPIServerClient) ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error) {
	if len(audiences) > 0 {
		return nil, fmt.Errorf("unexpected audiences %q", audiences)
	}
	status, ok := c.status[token]
	if !ok {
		return nil, errors.New("no status configured by test for token")
	}
	return status, nil
}
