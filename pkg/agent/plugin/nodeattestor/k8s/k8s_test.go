package k8s

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"

	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	k8scertutil "k8s.io/client-go/util/cert"
	k8scsr "k8s.io/client-go/util/certificate/csr"
)

const (
	trustDomain = "example.org"
)

func (s *Suite) marshal(obj interface{}) []byte {
	data, err := json.Marshal(obj)
	s.Require().NoError(err)
	return data
}

func (s *Suite) unmarshal(data []byte, obj interface{}) {
	s.Require().NoError(json.Unmarshal(data, obj))
}

func (s *Suite) errorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}

func (s *Suite) fetchAttestationData() (nodeattestor.FetchAttestationData_Stream, func()) {
	stream, err := s.p.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	return stream, func() {
		s.Require().NoError(stream.CloseSend())
	}
}

func signCSR(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	caCert, caKey, err := util.LoadCAFixture()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		Subject:               csr.Subject,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber:          big.NewInt(1234),

		RawSubject:  csr.RawSubject,
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to Marshall public key during Certificate signing: %v", err)
	}
	hash := sha1.Sum(pubBytes)
	template.SubjectKeyId = hash[:]

	bytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("Failed Creating certificate %v", err)
	}
	cert, err := x509.ParseCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to Parse cert after creation %v", err)
	}
	return cert[0], err
}

type Suite struct {
	suite.Suite

	p      *nodeattestor.BuiltIn
	client kubernetes.Interface
	cert   *x509.Certificate
}

func (s *Suite) SetupTest() {
	require := s.Require()

	// csr is enclosed by the two reactors
	var csr *certificates.CertificateSigningRequest

	createReactor := func(action k8stesting.Action) (bool, runtime.Object, error) {
		var err error
		csr = action.(k8stesting.CreateAction).GetObject().(*certificates.CertificateSigningRequest)
		if err != nil {
			return false, nil, err
		}
		return true, csr, nil
	}

	watchReactor := func(action k8stesting.Action) (bool, watch.Interface, error) {
		var err error
		watcher := watch.NewFakeWithChanSize(1, false)
		req, err := k8scsr.ParseCSR(csr)
		if err != nil {
			return false, nil, err
		}
		s.cert, err = signCSR(req)
		if err != nil {
			return false, nil, err
		}
		csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{Type: certificates.CertificateApproved})
		csr.Status.Certificate = k8scertutil.EncodeCertPEM(s.cert)
		watcher.Modify(csr)
		watcher.Stop()
		return true, watcher, nil
	}

	fakeClient := &fake.Clientset{}
	fakeClient.AddReactor("create", "certificatesigningrequests", createReactor)
	fakeClient.AddWatchReactor("certificatesigningrequests", watchReactor)

	s.client = fakeClient
	p := New()

	p.setConfig(&K8sConfig{TrustDomain: trustDomain})
	p.kubeClient = fakeClient
	s.p = nodeattestor.NewBuiltIn(p)
	require.NotNil(s.p)
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()
	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	type testParam struct {
		trustDomain       string
		privateKeyPath    string
		certificatePath   string
		caCertificatePath string
		expectedErr       string
	}
	testCases := []testParam{
		{"", "pkp", "cp", "cacp", "trust_domain is required"},
		{"td", "", "cp", "cacp", "private_key_path is required"},
		{"td", "pkp", "", "cacp", "certificate_path is required"},
		{"td", "pkp", "cp", "", "ca_certificate_path is required"},
		{"td", "pkp", "cp", "cacp", "no such file or directory"},
	}

	for _, t := range testCases {
		p := nodeattestor.NewBuiltIn(New())
		config := fmt.Sprintf(`
			trust_domain = %q
			k8s_private_key_path = %q
			k8s_certificate_path = %q
			k8s_ca_certificate_path = %q
			kubeconfig_path = "doesnotexist"`,
			t.trustDomain, t.privateKeyPath, t.certificatePath, t.caCertificatePath)

		resp, err := p.Configure(context.Background(), &plugin.ConfigureRequest{
			Configuration: config,
		})
		s.errorContains(err, t.expectedErr)
		require.Nil(resp)
	}
}

func (s *Suite) TestFetchAttestationDataSuccess() {
	require := s.Require()

	stream, done := s.fetchAttestationData()
	defer done()

	spiffeID := "spiffe://" + trustDomain + "/spire/agent/k8s/system/node/" + getAgentName()

	// first response has the spiffeid and attestation data
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(spiffeID, resp.SpiffeId)
	require.Equal("k8s", resp.AttestationData.Type)
	require.JSONEq(string(s.marshal(x509pop.AttestationData{
		Certificates: [][]byte{s.cert.Raw},
	})), string(resp.AttestationData.Data))
	require.Nil(resp.Response)

	// send a challenge
	challenge, err := x509pop.GenerateChallenge(s.cert)
	require.NoError(err)
	challengeBytes, err := json.Marshal(challenge)
	require.NoError(err)
	err = stream.Send(&nodeattestor.FetchAttestationDataRequest{
		Challenge: challengeBytes,
	})
	require.NoError(err)

	// recv the response
	resp, err = stream.Recv()
	require.NoError(err)
	require.Equal(spiffeID, resp.SpiffeId)
	require.Nil(resp.AttestationData)
	require.NotEmpty(resp.Response)

	// verify signature
	response := new(x509pop.Response)
	s.unmarshal(resp.Response, response)
	err = x509pop.VerifyChallengeResponse(s.cert.PublicKey, challenge, response)
	require.NoError(err)
}

func TestK8SAttestor(t *testing.T) {
	suite.Run(t, new(Suite))
}
