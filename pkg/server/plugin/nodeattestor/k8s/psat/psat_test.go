package psat

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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	k8s_apiserver_mock "github.com/spiffe/spire/test/mock/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

	notNil = gomock.Not(gomock.Nil())
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir        string
	fooKey     *rsa.PrivateKey
	fooSigner  jose.Signer
	barKey     *ecdsa.PrivateKey
	barSigner  jose.Signer
	bazSigner  jose.Signer
	attestor   nodeattestor.NodeAttestor
	mockCtrl   *gomock.Controller
	mockClient *k8s_apiserver_mock.MockClient
}

type TokenData struct {
	namespace          string
	serviceAccountName string
	podName            string
	podUID             string
	issuer             string
	audience           []string
	notBefore          time.Time
	expiry             time.Time
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
	s.mockCtrl = gomock.NewController(s.T())
	s.attestor = s.loadPlugin()
}

func (s *AttestorSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func (s *AttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor)
	s.attestor = attestor
	s.requireAttestError([]byte("{"), codes.FailedPrecondition, "nodeattestor(k8s_psat): not configured")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedPayload() {
	s.requireAttestError([]byte("{"), codes.InvalidArgument, "nodeattestor(k8s_psat): failed to unmarshal data payload")
}

func (s *AttestorSuite) TestAttestFailsWithNoClusterInPayload() {
	s.requireAttestError(makePayload("", "TOKEN"),
		codes.InvalidArgument,
		"nodeattestor(k8s_psat): missing cluster in attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithNoTokenInPayload() {
	s.requireAttestError(makePayload("FOO", ""),
		codes.InvalidArgument,
		"nodeattestor(k8s_psat): missing token in attestation data")
}

func (s *AttestorSuite) TestAttestFailsIfClusterNotConfigured() {
	s.requireAttestError(makePayload("CLUSTER", "blah"),
		codes.InvalidArgument,
		`nodeattestor(k8s_psat): not configured for cluster "CLUSTER"`)
}

func (s *AttestorSuite) TestAttestFailsIfTokenReviewAPIFails() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(nil, errors.New("an error"))
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): unable to validate token with TokenReview API")
}

func (s *AttestorSuite) TestAttestFailsIfTokenNotAuthenticated() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, false), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.PermissionDenied,
		"nodeattestor(k8s_psat): token not authenticated")
}

func (s *AttestorSuite) TestAttestFailsWithMissingNamespaceClaim() {
	tokenData := &TokenData{
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameClaim() {
	tokenData := &TokenData{
		namespace: "NS1",
		podName:   "PODNAME",
		podUID:    "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodNameClaim() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to get pod name from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodUIDClaim() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to get pod UID from token review status")
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotAllowed() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SERVICEACCOUNTNAME",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.PermissionDenied,
		`nodeattestor(k8s_psat): "NS1:SERVICEACCOUNTNAME" is not an allowed service account`)
}

func (s *AttestorSuite) TestAttestFailsIfCannotGetPod() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod(notNil, "NS1", "PODNAME").Return(nil, errors.New("an error"))
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to get pod from k8s API server")
}

func (s *AttestorSuite) TestAttestFailsIfCannotGetNode() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod(notNil, "NS1", "PODNAME").Return(createPod("NODENAME", "172.16.0.1"), nil)
	s.mockClient.EXPECT().GetNode(notNil, "NODENAME").Return(nil, errors.New("an error"))
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_psat): fail to get node from k8s API server")
}

func (s *AttestorSuite) TestAttestFailsIfNodeUIDIsEmpty() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod(notNil, "NS1", "PODNAME").Return(createPod("NODENAME", "172.16.0.1"), nil)
	s.mockClient.EXPECT().GetNode(notNil, "NODENAME").Return(createNode(""), nil)
	s.requireAttestError(makePayload("FOO", token),
		codes.Internal,
		"node UID is empty")
}

func (s *AttestorSuite) TestAttestSuccess() {
	// Success with FOO signed token
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME-1",
		podUID:             "PODUID-1",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod(notNil, "NS1", "PODNAME-1").Return(createPod("NODENAME-1", "172.16.10.1"), nil)
	s.mockClient.EXPECT().GetNode(notNil, "NODENAME-1").Return(createNode("NODEUID-1"), nil)

	result, err := s.attestor.Attest(context.Background(), makePayload("FOO", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_psat/FOO/NODEUID-1")
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:FOO"},
		{Type: "k8s_psat", Value: "agent_ns:NS1"},
		{Type: "k8s_psat", Value: "agent_sa:SA1"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-1"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-1"},
		{Type: "k8s_psat", Value: "agent_node_ip:172.16.10.1"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-1"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-1"},
		{Type: "k8s_psat", Value: "agent_node_label:NODELABEL-B:B"},
		{Type: "k8s_psat", Value: "agent_pod_label:PODLABEL-A:A"},
	}, result.Selectors)

	// Success with BAR signed token
	tokenData = &TokenData{
		namespace:          "NS2",
		serviceAccountName: "SA2",
		podName:            "PODNAME-2",
		podUID:             "PODUID-2",
	}
	token = s.signToken(s.barSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(notNil, token, []string{"AUDIENCE"}).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod(notNil, "NS2", "PODNAME-2").Return(createPod("NODENAME-2", "172.16.10.2"), nil)
	s.mockClient.EXPECT().GetNode(notNil, "NODENAME-2").Return(createNode("NODEUID-2"), nil)

	// Success with BAR signed token
	result, err = s.attestor.Attest(context.Background(), makePayload("BAR", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_psat/BAR/NODEUID-2")
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:BAR"},
		{Type: "k8s_psat", Value: "agent_ns:NS2"},
		{Type: "k8s_psat", Value: "agent_sa:SA2"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-2"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-2"},
		{Type: "k8s_psat", Value: "agent_node_ip:172.16.10.2"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-2"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-2"},
	}, result.Selectors)
}

func (s *AttestorSuite) TestConfigure() {
	doConfig := func(coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(s.T(), BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
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
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing trust domain
	err = doConfig(catalog.CoreConfig{}, "")
	s.RequireGRPCStatus(err, codes.InvalidArgument, "core configuration missing trust domain")

	// missing clusters
	err = doConfig(coreConfig, "")
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration must have at least one cluster")

	// cluster missing service account allow list
	err = doConfig(coreConfig, `clusters = {
			"FOO" = {}
		}`)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `cluster "FOO" configuration must have at least one service account allowed`)
}

func (s *AttestorSuite) signToken(signer jose.Signer, tokenData *TokenData) string {
	// Set default times for token when time is zero-valued
	if tokenData.notBefore.IsZero() {
		tokenData.notBefore = time.Now().Add(-time.Minute)
	}
	if tokenData.expiry.IsZero() {
		tokenData.expiry = time.Now().Add(time.Minute)
	}

	// build up standard claims
	claims := sat_common.PSATClaims{}
	claims.Issuer = tokenData.issuer
	claims.NotBefore = jwt.NewNumericDate(tokenData.notBefore)
	claims.Expiry = jwt.NewNumericDate(tokenData.expiry)
	claims.Audience = tokenData.audience

	// build up psat claims
	claims.K8s.Namespace = tokenData.namespace
	claims.K8s.ServiceAccount.Name = tokenData.serviceAccountName
	claims.K8s.Pod.Name = tokenData.podName
	claims.K8s.Pod.UID = tokenData.podUID

	builder := jwt.Signed(signer)
	builder = builder.Claims(claims)

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *AttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	attestor := New()
	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1, plugintest.Configure(`
		clusters = {
			"FOO" = {
				service_account_allow_list = ["NS1:SA1"]
				kube_config_file = ""
				allowed_pod_label_keys = ["PODLABEL-A"]
				allowed_node_label_keys = ["NODELABEL-B"]
			}
			"BAR" = {
				service_account_allow_list = ["NS2:SA2"]
				kube_config_file= ""
				audience = ["AUDIENCE"]
			}
		}
	`), plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}))

	// TODO: provide this client in a cleaner way
	s.mockClient = k8s_apiserver_mock.NewMockClient(s.mockCtrl)
	attestor.config.clusters["FOO"].client = s.mockClient
	attestor.config.clusters["BAR"].client = s.mockClient
	return v1
}

func (s *AttestorSuite) fooCertPath() string {
	return filepath.Join(s.dir, "foo.pem")
}

func (s *AttestorSuite) barCertPath() string {
	return filepath.Join(s.dir, "bar.pem")
}

func (s *AttestorSuite) requireAttestError(payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.RequireGRPCStatusContains(err, expectCode, expectMsg)
	s.Require().Nil(result)
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

func createTokenStatus(tokenData *TokenData, authenticated bool) *authv1.TokenReviewStatus {
	values := make(map[string]authv1.ExtraValue)
	values["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue([]string{tokenData.podName})
	values["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue([]string{tokenData.podUID})
	return &authv1.TokenReviewStatus{
		Authenticated: authenticated,
		User: authv1.UserInfo{
			Username: fmt.Sprintf("system:serviceaccount:%s:%s", tokenData.namespace, tokenData.serviceAccountName),
			Extra:    values,
		},
	}
}

func createPod(nodeName string, hostIP string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"PODLABEL-A": "A",
				"PODLABEL-B": "B",
			},
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
		Status: v1.PodStatus{
			HostIP: hostIP,
		},
	}
}

func createNode(nodeUID string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID(nodeUID),
			Labels: map[string]string{
				"NODELABEL-A": "A",
				"NODELABEL-B": "B",
			},
		},
	}
}

func expectNoChallenge(ctx context.Context, challenge []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
