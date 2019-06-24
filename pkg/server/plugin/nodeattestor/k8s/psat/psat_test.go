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
	"io/ioutil"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	k8s_apiserver_mock "github.com/spiffe/spire/test/mock/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
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
	attestor   nodeattestor.Plugin
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

	s.barKey, err = pemutil.ParseECPrivateKey(barKeyPEM)
	s.Require().NoError(err)
	s.barSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       s.barKey,
	}, nil)

	bazKey, err := pemutil.ParseECPrivateKey(bazKeyPEM)
	s.Require().NoError(err)
	s.bazSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       bazKey,
	}, nil)

	s.dir = s.TempDir()

	// generate a self-signed certificate for signing tokens
	s.Require().NoError(createAndWriteSelfSignedCert("FOO", s.fooKey, s.fooCertPath()))
	s.Require().NoError(createAndWriteSelfSignedCert("BAR", s.barKey, s.barCertPath()))
}

func (s *AttestorSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.attestor = s.configureAttestor()
}

func (s *AttestorSuite) TeardownTest() {
	s.mockCtrl.Finish()
}

func (s *AttestorSuite) TestAttestFailsWhenNotConfigured() {
	resp, err := s.doAttestOnAttestor(s.newAttestor(), &nodeattestor.AttestRequest{})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: not configured")
	s.Require().Nil(resp)
}

func (s *AttestorSuite) TestAttestFailsWithNoAttestationData() {
	s.requireAttestError(&nodeattestor.AttestRequest{},
		"k8s-psat: missing attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithWrongAttestationDataType() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "blah",
		},
	}, `k8s-psat: unexpected attestation data type "blah"`)
}

func (s *AttestorSuite) TestAttestFailsWithNoAttestationDataPayload() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "k8s_psat",
		},
	}, "k8s-psat: missing attestation data payload")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedAttestationDataPayload() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "k8s_psat",
			Data: []byte("{"),
		},
	}, "k8s-psat: failed to unmarshal data payload")
}

func (s *AttestorSuite) TestAttestFailsWithNoCluster() {
	s.requireAttestError(makeAttestRequest("", "TOKEN"),
		"k8s-psat: missing cluster in attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithNoToken() {
	s.requireAttestError(makeAttestRequest("FOO", ""),
		"k8s-psat: missing token in attestation data")
}

func (s *AttestorSuite) TestAttestFailsIfClusterNotConfigured() {
	s.requireAttestError(makeAttestRequest("CLUSTER", "blah"),
		`k8s-psat: not configured for cluster "CLUSTER"`)
}

func (s *AttestorSuite) TestAttestFailsIfTokenReviewAPIFails() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(nil, errors.New("an error"))
	s.requireAttestError(makeAttestRequest("FOO", token), "unable to validate token with TokenReview API")
}

func (s *AttestorSuite) TestAttestFailsIfTokenNotAuthenticated() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, false), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "token not authenticated")
}

func (s *AttestorSuite) TestAttestFailsWithMissingNamespaceClaim() {
	tokenData := &TokenData{
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameClaim() {
	tokenData := &TokenData{
		namespace: "NS1",
		podName:   "PODNAME",
		podUID:    "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodNameClaim() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to get pod name from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodUIDClaim() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to get pod UID from token review status")
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotWhitelisted() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SERVICEACCOUNTNAME",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), `"NS1:SERVICEACCOUNTNAME" is not a whitelisted service account`)
}

func (s *AttestorSuite) TestAttestFailsIfCannotGetPod() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod("NS1", "PODNAME").Return(nil, errors.New("an error"))
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to get pod from k8s API server")
}

func (s *AttestorSuite) TestAttestFailsIfCannotGetNode() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod("NS1", "PODNAME").Return(createPod("NODENAME"), nil)
	s.mockClient.EXPECT().GetNode("NODENAME").Return(nil, errors.New("an error"))
	s.requireAttestError(makeAttestRequest("FOO", token), "fail to get node from k8s API server")
}

func (s *AttestorSuite) TestAttestFailsIfNodeUIDIsEmpty() {
	tokenData := &TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "PODNAME",
		podUID:             "PODUID",
	}
	token := s.signToken(s.fooSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod("NS1", "PODNAME").Return(createPod("NODENAME"), nil)
	s.mockClient.EXPECT().GetNode("NODENAME").Return(createNode(""), nil)
	s.requireAttestError(makeAttestRequest("FOO", token), "node UID is empty")
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
	s.mockClient.EXPECT().ValidateToken(token, defaultAudience).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod("NS1", "PODNAME-1").Return(createPod("NODENAME-1"), nil)
	s.mockClient.EXPECT().GetNode("NODENAME-1").Return(createNode("NODEUID-1"), nil)

	resp, err := s.doAttest(makeAttestRequest("FOO", token))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(resp.AgentId, "spiffe://example.org/spire/agent/k8s_psat/FOO/NODEUID-1")
	s.Require().Nil(resp.Challenge)
	s.Require().Equal([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:FOO"},
		{Type: "k8s_psat", Value: "agent_ns:NS1"},
		{Type: "k8s_psat", Value: "agent_sa:SA1"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-1"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-1"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-1"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-1"},
	}, resp.Selectors)

	// Success with BAR signed token
	tokenData = &TokenData{
		namespace:          "NS2",
		serviceAccountName: "SA2",
		podName:            "PODNAME-2",
		podUID:             "PODUID-2",
	}
	token = s.signToken(s.barSigner, tokenData)
	s.mockClient.EXPECT().ValidateToken(token, []string{"AUDIENCE"}).Return(createTokenStatus(tokenData, true), nil)
	s.mockClient.EXPECT().GetPod("NS2", "PODNAME-2").Return(createPod("NODENAME-2"), nil)
	s.mockClient.EXPECT().GetNode("NODENAME-2").Return(createNode("NODEUID-2"), nil)

	// Success with FOO signed token
	resp, err = s.doAttest(makeAttestRequest("BAR", token))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(resp.AgentId, "spiffe://example.org/spire/agent/k8s_psat/BAR/NODEUID-2")
	s.Require().Nil(resp.Challenge)
	s.Require().Equal([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:BAR"},
		{Type: "k8s_psat", Value: "agent_ns:NS2"},
		{Type: "k8s_psat", Value: "agent_sa:SA2"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-2"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-2"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-2"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-2"},
	}, resp.Selectors)
}

func (s *AttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.RequireErrorContains(err, "k8s-psat: unable to decode configuration")
	s.Require().Nil(resp)

	// missing global configuration
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: global configuration missing trust domain")
	s.Require().Nil(resp)

	// missing clusters
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: configuration must have at least one cluster")
	s.Require().Nil(resp)

	// cluster missing service account whitelist
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprint(`clusters = {
			"FOO" = {}
		}`),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, `k8s-psat: cluster "FOO" configuration must have at least one service account whitelisted`)
	s.Require().Nil(resp)

	// success with two CERT based key files
	s.configureAttestor()
}

func (s *AttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
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

func (s *AttestorSuite) newAttestor() nodeattestor.Plugin {
	var plugin nodeattestor.Plugin
	s.LoadPlugin(BuiltIn(), &plugin)
	return plugin
}

func (s *AttestorSuite) configureAttestor() nodeattestor.Plugin {
	attestor := New()

	resp, err := attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprint(`
		clusters = {
			"FOO" = {
				service_account_whitelist = ["NS1:SA1"]
				kube_config_file = ""
			}
			"BAR" = {
				service_account_whitelist = ["NS2:SA2"]
				kube_config_file= ""
				audience = ["AUDIENCE"]
			}
		}
		`),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	s.mockClient = k8s_apiserver_mock.NewMockClient(s.mockCtrl)
	attestor.config.clusters["FOO"].client = s.mockClient
	attestor.config.clusters["BAR"].client = s.mockClient

	var plugin nodeattestor.Plugin
	s.LoadPlugin(builtin(attestor), &plugin)
	return plugin
}

func (s *AttestorSuite) doAttest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	return s.doAttestOnAttestor(s.attestor, req)
}

func (s *AttestorSuite) doAttestOnAttestor(attestor nodeattestor.Plugin, req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	stream, err := attestor.Attest(context.Background())
	s.Require().NoError(err)

	err = stream.Send(req)
	s.Require().NoError(err)

	err = stream.CloseSend()
	s.Require().NoError(err)

	return stream.Recv()
}

func (s *AttestorSuite) requireAttestError(req *nodeattestor.AttestRequest, contains string) {
	resp, err := s.doAttest(req)
	s.RequireErrorContains(err, contains)
	s.Require().Nil(resp)
}

func makeAttestRequest(cluster, token string) *nodeattestor.AttestRequest {
	return &nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "k8s_psat",
			Data: []byte(fmt.Sprintf(`{"cluster": %q, "token": %q}`, cluster, token)),
		},
	}
}

func (s *AttestorSuite) fooCertPath() string {
	return filepath.Join(s.dir, "foo.pem")
}

func (s *AttestorSuite) barCertPath() string {
	return filepath.Join(s.dir, "bar.pem")
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
	if err := ioutil.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		return err
	}
	return nil
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

func createPod(nodeName string) *v1.Pod {
	return &v1.Pod{
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}
}

func createNode(nodeUID string) *v1.Node {
	node := &v1.Node{}
	node.UID = types.UID(nodeUID)
	return node
}
