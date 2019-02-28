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
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	k8s_cli_mock "github.com/spiffe/spire/test/mock/common/plugin/k8s/client"
	"github.com/stretchr/testify/suite"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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
	suite.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	suite.Suite

	dir       string
	fooKey    *rsa.PrivateKey
	fooSigner jose.Signer
	barKey    *ecdsa.PrivateKey
	barSigner jose.Signer
	bazSigner jose.Signer
	attestor  *nodeattestor.BuiltIn
	mockCtrl  *gomock.Controller
}

type TokenData struct {
	namespace          string
	serviceAccountName string
	podName            string
	podUID             string
	audience           []string
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

	s.dir, err = ioutil.TempDir("", "spire-server-nodeattestor-k8s-psat-")
	s.Require().NoError(err)

	// generate a self-signed certificate for signing tokens
	s.Require().NoError(createAndWriteSelfSignedCert("FOO", s.fooKey, s.fooCertPath()))
	s.Require().NoError(createAndWriteSelfSignedCert("BAR", s.barKey, s.barCertPath()))

}

func (s *AttestorSuite) TearDownSuite() {
	os.RemoveAll(s.dir)
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
	s.Require().EqualError(err, "k8s-psat: not configured")
	s.Require().Nil(resp)
}

func (s *AttestorSuite) TestAttestFailsWhenAttestedBefore() {
	s.requireAttestError(&nodeattestor.AttestRequest{AttestedBefore: true},
		"k8s-psat: node has already attested")
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

func (s *AttestorSuite) TestAttestFailsWithMalformedToken() {
	s.requireAttestError(makeAttestRequest("FOO", "blah"),
		"k8s-psat: unable to parse token")
}

func (s *AttestorSuite) TestAttestFailsIfClusterNotConfigured() {
	s.requireAttestError(makeAttestRequest("CLUSTER", "blah"),
		`k8s-psat: not configured for cluster "CLUSTER"`)
}

func (s *AttestorSuite) TestAttestFailsWithBadSignature() {
	// sign a token and replace the signature
	token := s.signToken(s.fooSigner, TokenData{})
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3)
	parts[2] = "aaaa"
	token = strings.Join(parts, ".")

	s.requireAttestError(makeAttestRequest("FOO", token),
		"unable to verify token")
}

func (s *AttestorSuite) TestAttestFailsWithInvalidIssuer() {
	token, err := jwt.Signed(s.fooSigner).CompactSerialize()
	s.Require().NoError(err)
	s.requireAttestError(makeAttestRequest("FOO", token), "invalid issuer claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingNamespaceClaim() {
	token := s.signToken(s.fooSigner, TokenData{})
	s.requireAttestError(makeAttestRequest("FOO", token), "token missing namespace claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameClaim() {
	token := s.signToken(s.fooSigner,
		TokenData{
			namespace: "NAMESPACE",
			podName:   "PODNAME",
			podUID:    "PODUID",
		})
	s.requireAttestError(makeAttestRequest("FOO", token), "token missing service account name claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodNameClaim() {
	token := s.signToken(s.fooSigner,
		TokenData{
			namespace:          "NAMESPACE",
			serviceAccountName: "SERVICEACCOUNTNAME",
			podUID:             "PODUID",
		})
	s.requireAttestError(makeAttestRequest("FOO", token), "token missing pod name claim")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodUIDClaim() {
	token := s.signToken(s.fooSigner,
		TokenData{
			namespace:          "NAMESPACE",
			serviceAccountName: "SERVICEACCOUNTNAME",
			podName:            "PODNAME",
		})
	s.requireAttestError(makeAttestRequest("FOO", token), "token missing pod UID claim")
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotWhitelisted() {
	token := s.signToken(s.fooSigner,
		TokenData{
			namespace:          "NAMESPACE",
			serviceAccountName: "SERVICEACCOUNTNAME",
			podName:            "PODNAME",
			podUID:             "PODUID",
		})
	s.requireAttestError(makeAttestRequest("FOO", token), `"NAMESPACE:SERVICEACCOUNTNAME" is not a whitelisted service account`)
}

func (s *AttestorSuite) TestAttestFailsIfTokenSignatureCannotBeVerifiedByCluster() {
	token := s.signToken(s.bazSigner, TokenData{
		namespace:          "NAMESPACE",
		serviceAccountName: "SERVICEACCOUNTNAME",
		podName:            "PODNAME",
		podUID:             "PODUID",
	})
	s.requireAttestError(makeAttestRequest("FOO", token), "k8s-psat: unable to verify token")
}

func (s *AttestorSuite) TestAttestSuccess() {
	// Success with FOO signed token
	resp, err := s.doAttest(s.signAttestRequest(s.fooSigner, "FOO", TokenData{
		namespace:          "NS1",
		serviceAccountName: "SA1",
		podName:            "podname-1",
		podUID:             "poduid-1",
	}))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().True(resp.Valid)
	s.Require().Equal(resp.BaseSPIFFEID, "spiffe://example.org/spire/agent/k8s_psat/FOO/poduid-1")
	s.Require().Nil(resp.Challenge)
	s.Require().Equal([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:FOO"},
		{Type: "k8s_psat", Value: "agent_ns:NS1"},
		{Type: "k8s_psat", Value: "agent_sa:SA1"},
		{Type: "k8s_psat", Value: "agent_pod_name:podname-1"},
		{Type: "k8s_psat", Value: "agent_pod_uid:poduid-1"},
		{Type: "k8s_psat", Value: "agent_node_name:node-1"},
	}, resp.Selectors)

	// Success with BAR signed token
	resp, err = s.doAttest(s.signAttestRequest(s.barSigner, "BAR",
		TokenData{
			namespace:          "NS2",
			serviceAccountName: "SA2",
			podName:            "podname-2",
			podUID:             "poduid-2",
			audience:           []string{"spire-server"},
		}))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().True(resp.Valid)
	s.Require().Equal(resp.BaseSPIFFEID, "spiffe://example.org/spire/agent/k8s_psat/BAR/poduid-2")
	s.Require().Nil(resp.Challenge)
	s.Require().Equal([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:BAR"},
		{Type: "k8s_psat", Value: "agent_ns:NS2"},
		{Type: "k8s_psat", Value: "agent_sa:SA2"},
		{Type: "k8s_psat", Value: "agent_pod_name:podname-2"},
		{Type: "k8s_psat", Value: "agent_pod_uid:poduid-2"},
	}, resp.Selectors)
}

func (s *AttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.requireErrorContains(err, "k8s-psat: unable to decode configuration")
	s.Require().Nil(resp)

	// missing global configuration
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().EqualError(err, "k8s-psat: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.Require().EqualError(err, "k8s-psat: global configuration missing trust domain")
	s.Require().Nil(resp)

	// missing clusters
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().EqualError(err, "k8s-psat: configuration must have at least one cluster")
	s.Require().Nil(resp)

	// cluster missing service account key file
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `clusters = {
			"FOO" = {}
		}`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().EqualError(err, `k8s-psat: cluster "FOO" configuration missing service account keys file`)
	s.Require().Nil(resp)

	// cluster missing service account whitelist
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`clusters = {
			"FOO" = {
				service_account_key_file = %q
			}
		}`, s.fooCertPath()),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().EqualError(err, `k8s-psat: cluster "FOO" configuration must have at least one service account whitelisted`)
	s.Require().Nil(resp)

	// unable to load api server cert file
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`clusters = {
			"FOO" = {
				service_account_key_file = %q
				service_account_whitelist = ["A"]
			}
		}`, filepath.Join(s.dir, "missing.pem")),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.requireErrorContains(err, `k8s-psat: failed to load cluster "FOO" service account keys`)
	s.Require().Nil(resp)

	// no keys in PEM file
	s.Require().NoError(ioutil.WriteFile(filepath.Join(s.dir, "nokeys.pem"), []byte{}, 0644))
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`clusters = {
			"FOO" = {
				service_account_key_file = %q
				service_account_whitelist = ["A"]
			}
		}`, filepath.Join(s.dir, "nokeys.pem")),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.requireErrorContains(err, `k8s-psat: cluster "FOO" has no service account keys`)
	s.Require().Nil(resp)

	// success with two CERT based key files
	s.configureAttestor()
}

func (s *AttestorSuite) TestServiceAccountKeyFileAlternateEncodings() {
	fooPKCS1KeyPath := filepath.Join(s.dir, "foo-pkcs1.pem")
	fooPKCS1Bytes := x509.MarshalPKCS1PublicKey(&s.fooKey.PublicKey)
	s.Require().NoError(ioutil.WriteFile(fooPKCS1KeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: fooPKCS1Bytes,
	}), 0644))

	fooPKIXKeyPath := filepath.Join(s.dir, "foo-pkix.pem")
	fooPKIXBytes, err := x509.MarshalPKIXPublicKey(s.fooKey.Public())
	s.Require().NoError(err)
	s.Require().NoError(ioutil.WriteFile(fooPKIXKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: fooPKIXBytes,
	}), 0644))

	barPKIXKeyPath := filepath.Join(s.dir, "bar-pkix.pem")
	barPKIXBytes, err := x509.MarshalPKIXPublicKey(s.barKey.Public())
	s.Require().NoError(err)
	s.Require().NoError(ioutil.WriteFile(barPKIXKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: barPKIXBytes,
	}), 0644))

	_, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`clusters = {
			"FOO-PKCS1" = {
				service_account_key_file = %q
				service_account_whitelist = ["A"]
			}
			"FOO-PKIX" = {
				service_account_key_file = %q
				service_account_whitelist = ["A"]
			}
			"BAR-PKIX" = {
				service_account_key_file = %q
				service_account_whitelist = ["A"]
			}
		}`, fooPKCS1KeyPath, fooPKIXKeyPath, barPKIXKeyPath),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
}

func (s *AttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *AttestorSuite) signToken(signer jose.Signer, tokenData TokenData) string {
	builder := jwt.Signed(signer)

	// build up standard claims
	claims := sat_common.PSATClaims{}
	claims.Issuer = "api"
	claims.NotBefore = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	claims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Minute))
	claims.Audience = tokenData.audience

	// build up psat claims
	claims.K8s.Namespace = tokenData.namespace
	claims.K8s.ServiceAccount.Name = tokenData.serviceAccountName
	claims.K8s.Pod.Name = tokenData.podName
	claims.K8s.Pod.UID = tokenData.podUID

	builder = builder.Claims(claims)

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *AttestorSuite) signAttestRequest(signer jose.Signer, cluster string, tokenData TokenData) *nodeattestor.AttestRequest {
	return makeAttestRequest(cluster, s.signToken(signer, tokenData))
}

func (s *AttestorSuite) newAttestor() *nodeattestor.BuiltIn {
	attestor := NewAttestorPlugin()
	return nodeattestor.NewBuiltIn(attestor)
}

func (s *AttestorSuite) configureAttestor() *nodeattestor.BuiltIn {

	attestor := NewAttestorPlugin()

	resp, err := attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
		clusters = {
			"FOO" = {
				service_account_key_file = %q
				service_account_whitelist = ["NS1:SA1"]
				enable_api_server_queries = true
				kube_config_file = ""
				audience = []
			}
			"BAR" = {
				service_account_key_file = %q
				service_account_whitelist = ["NS2:SA2"]
				enable_api_server_queries = false
				kube_config_file= ""
			}
		}
		`, s.fooCertPath(), s.barCertPath()),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	fooMock := k8s_cli_mock.NewMockK8SClient(s.mockCtrl)
	fooMock.EXPECT().GetNode("NS1", "podname-1").Return("node-1", nil).AnyTimes()
	attestor.config.clusters["FOO"].k8sClient = fooMock

	barMock := k8s_cli_mock.NewMockK8SClient(s.mockCtrl)
	barMock.EXPECT().GetNode("NS2", "podname-2").Return("node-2", nil).AnyTimes()
	attestor.config.clusters["BAR"].k8sClient = barMock

	return nodeattestor.NewBuiltIn(attestor)
}

func (s *AttestorSuite) doAttest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	return s.doAttestOnAttestor(s.attestor, req)
}

func (s *AttestorSuite) doAttestOnAttestor(attestor *nodeattestor.BuiltIn, req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
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
	s.requireErrorContains(err, contains)
	s.Require().Nil(resp)
}

func (s *AttestorSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
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
