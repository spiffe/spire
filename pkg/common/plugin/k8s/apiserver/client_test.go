package apiserver

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	mock_clientset "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset"
	mock_authv1 "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset/authenticationv1"
	mock_tokenreview "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset/authenticationv1/tokenreview"
	mock_corev1 "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset/corev1"
	mock_node "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset/corev1/node"
	mock_pod "github.com/spiffe/spire/test/mock/common/plugin/k8s/clientset/corev1/pod"
	"github.com/spiffe/spire/test/spiretest"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	ctx = context.Background()

	kubeConfig = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority: %s
    server: https://192.168.99.100:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: minikube
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: %s
    client-key: %s

`

	kubeConfigCA = []byte(`-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTE5MDIyMTIxNTkyN1oXDTI5MDIxOTIxNTkyN1owFTETMBEGA1UE
AxMKbWluaWt1YmVDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ+
0nen9K1fW37Z3FLMcuiVRZo9/R9t6yxupYgCufh3GEZxxdkUVAxyszgWaXelv8tz
/UNDbOGsps1EHq9ZS8XoAZOiaBPNBmHtTlCx1muYq/KvOMgFdau0VxcN58p3pCKE
QAgkyXtTVN6KMIWlRiplgYBrbcfQOD7h83hmRahBRJfJMSazsVdul53W6MO6e4I4
BLr8BK48Q4NT8kqTmhycdnSPUIDFWr2QKajRAaIRZ8vrCsd873O394q/OUEgDDhZ
Vyum3c9xcFXjcZTzXBFoBnh4pCy3mTGm6CfBHCdoLDJVjxFKFZVUQpePopq8Wpzb
7bbrAoD0wKODjLTjrlcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQBVFt+D2HbMjRSqCtnhcouVFjgBaimyoGZ3AC9P5/cYq+tDn+Z5
6QEZrQbHkjBEYa75QFyXKspINBGtK+/WCtyJDddHcHPvESfiGCkLEhYDGvcIOKZo
QwhKgBCS1qtulZ2941ibsWFcCkeyWmYOFk2xM61TDlDOvDt9fddajeQxl35/kpav
rL4t8ScOOzuR2BD7WqddlPOKvunXk69qJgcF21jQxgZ7tN7A5L+fvII8ejh9WtED
CNAbQTAD+xlfKysnmkI9QjyNA5h3EbsJUkIZUfVqHQylCbLPl60QzOYO1w0KFce5
nyVUQ3FRUaFHuiHf0mZPGkuIV/O63pLkT7fJ
-----END CERTIFICATE-----`)

	kubeConfigClientCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTE5MDQzMDEyNDkxNloXDTIwMDQzMDEyNDkxNlowMTEXMBUGA1UE
ChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIMCT2+uEDVfz8BNUoE5wa4mAqr8QL
kJknjUFS3kdRke/SIiuPgAi1GaQK4XkT24fTIqYO8YwlwSYcsymJ0E/KHzns+kfn
OS4ls0fXibkB2lw36q6VltNkBGs7fwD0De6DP+PP/89eTSStXaqfz5lmpbjdsUM6
P8zeMgkJoPNdf1bYikdRwAVuhhdW1pFbHNVdqQMCVFYwhWrav5r8RBHERR7aUwx4
T3RMPtN9yb6OPLVrycUKHEi8N5J4aYwczu2QZ/AUdriapB4QrdL1ePkBI0q0LOww
2RDbfPKd/Y5N9FFbTAkJie9TaiffhxW9FTYz/OJlhKBALH9InKYoatNLAgMBAAGj
PzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAQ4S/JRl7IqKHCEuN
TEhEGAs7A2DJLrKM1zVUeP4LHSXdQG9px0oaGvONAgKjtY+3j1ajecCPKHeduVJ2
RFOqlR0jx74vnwat/C9ELAlFAyvwRzVMxoF1a3SuAq1D62MU3smD03X3WOlUrgpU
Ispvk1GICnSys++AacjyNTKlRUUheDdSObHQpYt7MOl1nygHl9HpGWxvTaXCiz2y
RZUI/exII+oNBrwRv2b3Hmflm5sG93siVSvZ0EXI27O3NjvJBPryKyJ/9A6uq975
G8cDWzZ5QYzlKr1qcuYaP5Aw7DbMVIU17vVACili6R9WD9+wk2rjSmS737YJ+Ud9
vOjlQw==
-----END CERTIFICATE-----`)

	kubeConfigClientKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyDAk9vrhA1X8/ATVKBOcGuJgKq/EC5CZJ41BUt5HUZHv0iIr
j4AItRmkCuF5E9uH0yKmDvGMJcEmHLMpidBPyh857PpH5zkuJbNH14m5AdpcN+qu
lZbTZARrO38A9A3ugz/jz//PXk0krV2qn8+ZZqW43bFDOj/M3jIJCaDzXX9W2IpH
UcAFboYXVtaRWxzVXakDAlRWMIVq2r+a/EQRxEUe2lMMeE90TD7Tfcm+jjy1a8nF
ChxIvDeSeGmMHM7tkGfwFHa4mqQeEK3S9Xj5ASNKtCzsMNkQ23zynf2OTfRRW0wJ
CYnvU2on34cVvRU2M/ziZYSgQCx/SJymKGrTSwIDAQABAoIBAQCQdp3WVcmXnLAK
NnqUh0I57G81ns29AsZjUn53jMyuwr/sRphk4CJofm5xI7E6cUwdQ33OfuWCQVZ9
k5VATMGnvM0ShLLq28q/jhckJdEK00eFWqhObx9xp/ayYr6PYJZkxPBjo9lD1ivH
qDZ/SVMMTj+QTGGVYYE4P6dh+XJmXzvIHVJmG2ZClSlHeNAze+WygkOykZnQF1do
JvqBxl5YHUM8PSJ2xnMYpHVFJkmAp0GntpgxgxR6yBPLroQSeU/SJUQBhinstQ++
v9P3E5eq4VTDGjWZYzAg95boLGowhsQupNHMmc3TqqJkXpGPaXzFe/O5ZiVzrJ8y
UlVye7dxAoGBAMpyqXE4ctfN1hNRqFwsj23MKZMekOUk9vXZiWkguIep48zp8PSy
hThl+h37ddk5jqRA8aiVeMXkvaIzs2b/8wezuu+4xtCdPEdZu/xAw4x0yJ5Uv0E1
Ci6y0bBmcV0zv4fRsNvErMAkUU8bo2oPbNT9siRRfi/HEQTjC5gnCwZtAoGBAP0k
c46TQZ07YccWskDDkf/KAlqBCPlo6ar/CJp0Djqjap9/mNMl0lJV7dpy/WS0BP9S
LyQb5FYsv7ga3iMdi1oEGQsEc31nePDyYZRp/aD0MNgQUXv60Zevyd05NSkTRb9i
0ob5vALuOczqjeL3YF1oLH0HZyG0bs+oCkjL4I2XAoGAMcodbiEJ7ZVMDxhIJdM3
uzM5Dlu4GwMKUdCcgORxPbxEsELg5e154jMCXplXlIMZV8A5LtMEDveAxAGfH7fX
F4/Wa9qv2uKwzoN9Pj7XWRXnuTjyiKD4zh9gftfTDa8Kbebebk5ihibocGJFwHHm
vENgqpn4RNvaja8hTNxdU8kCgYBTKlWYosJswKSX/tnjMx1VNu3dBAWJwzD5j74o
2DYQh72w1v/DZuqZSEfTe/HJ0ubNZxe7ujojIaJ+/ry6NqugkDYWC4lRytvN9SOf
2c6MwY0Gfx32KGoRdpxQRMo1S3KftPzLgWKGZ/OvYePpjDIpnd732KXGSfwZ1vBC
CFEm0wKBgQCwARG9qV4sUoBvwLyBHQbPFZi/9PYwvDsnzjmKTUPa+kd4ATrv7gBY
oN1CqmWqJQYVB6oGxFMaebeijY82beDN3WSBAK2FGvmdi3vZUAHHXyNOBS2Wq6PA
oIrPuyjOmscrC627wX3LGUHwPKtNArBT8lKFfda1B1BqAk0q1/ui/A==
-----END RSA PRIVATE KEY-----`)
)

const (
	testToken = "TEST-TOKEN"
)

func TestAPIServerClient(t *testing.T) {
	spiretest.Run(t, new(ClientSuite))
}

type ClientSuite struct {
	spiretest.Suite
	dir              string
	mockCtrl         *gomock.Controller
	mockClientset    *mock_clientset.MockInterface
	mockCoreV1       *mock_corev1.MockCoreV1Interface
	mockPods         *mock_pod.MockPodInterface
	mockNodes        *mock_node.MockNodeInterface
	mockAuthV1       *mock_authv1.MockAuthenticationV1Interface
	mockTokenReviews *mock_tokenreview.MockTokenReviewInterface
}

func (s *ClientSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockClientset = mock_clientset.NewMockInterface(s.mockCtrl)
	s.mockCoreV1 = mock_corev1.NewMockCoreV1Interface(s.mockCtrl)
	s.mockPods = mock_pod.NewMockPodInterface(s.mockCtrl)
	s.mockNodes = mock_node.NewMockNodeInterface(s.mockCtrl)
	s.mockAuthV1 = mock_authv1.NewMockAuthenticationV1Interface(s.mockCtrl)
	s.mockTokenReviews = mock_tokenreview.NewMockTokenReviewInterface(s.mockCtrl)

	var err error
	s.dir, err = ioutil.TempDir("", "spire-k8s-client-test-")
	s.Require().NoError(err)
}

func (s *ClientSuite) TearDownTest() {
	s.mockCtrl.Finish()
	os.RemoveAll(s.dir)
}

func (s *ClientSuite) TestGetPodFailsIfNamespaceIsEmpty() {
	client := New("")
	pod, err := client.GetPod(ctx, "", "POD-NAME")
	s.AssertErrorContains(err, "empty namespace")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodFailsIfPodNameIsEmpty() {
	client := New("")
	pod, err := client.GetPod(ctx, "NAMESPACE", "")
	s.AssertErrorContains(err, "empty pod name")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodFailsToLoadClient() {
	client := s.createDefectiveClient("")
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.AssertErrorContains(err, "unable to get clientset")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodFailsIfGetsErrorFromAPIServer() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Pods("NAMESPACE").Return(s.mockPods).Times(1)
	s.mockPods.EXPECT().Get(ctx, "PODNAME", metav1.GetOptions{}).Return(nil, errors.New("an error"))

	client := s.createClient()
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.AssertErrorContains(err, "unable to query pods API")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodFailsIfGetsNilPod() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Pods("NAMESPACE").Return(s.mockPods).Times(1)
	s.mockPods.EXPECT().Get(ctx, "PODNAME", metav1.GetOptions{}).Return(nil, nil)

	client := s.createClient()
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.AssertErrorContains(err, "got nil pod for pod name: PODNAME")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodSucceeds() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Pods("NAMESPACE").Return(s.mockPods).Times(1)
	expectedPod := createPod("PODNAME")
	s.mockPods.EXPECT().Get(ctx, "PODNAME", metav1.GetOptions{}).Return(expectedPod, nil)

	client := s.createClient()
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.NoError(err)
	s.Equal(expectedPod, pod)
}

func (s *ClientSuite) TestGetNodeFailsIfNodeNameIsEmpty() {
	client := New("")
	node, err := client.GetNode(ctx, "")
	s.AssertErrorContains(err, "empty node name")
	s.Nil(node)
}

func (s *ClientSuite) TestGetNodeFailsToLoadClient() {
	client := s.createDefectiveClient("")
	node, err := client.GetNode(ctx, "NODENAME")
	s.AssertErrorContains(err, "unable to get clientset")
	s.Nil(node)
}

func (s *ClientSuite) TestGetNodeFailsIfGetsErrorFromAPIServer() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Nodes().Return(s.mockNodes).Times(1)
	s.mockNodes.EXPECT().Get(ctx, "NODENAME", metav1.GetOptions{}).Return(nil, errors.New("an error"))

	client := s.createClient()
	node, err := client.GetNode(ctx, "NODENAME")
	s.AssertErrorContains(err, "unable to query nodes API")
	s.Nil(node)
}

func (s *ClientSuite) TestGetNodeFailsIfGetsNilNode() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Nodes().Return(s.mockNodes).Times(1)
	s.mockNodes.EXPECT().Get(ctx, "NODENAME", metav1.GetOptions{}).Return(nil, nil)

	client := s.createClient()
	node, err := client.GetNode(ctx, "NODENAME")
	s.AssertErrorContains(err, "got nil node for node name: NODENAME")
	s.Nil(node)
}

func (s *ClientSuite) TestGetNodeSucceeds() {
	s.mockClientset.EXPECT().CoreV1().Return(s.mockCoreV1).Times(1)
	s.mockCoreV1.EXPECT().Nodes().Return(s.mockNodes).Times(1)
	expectedNode := createNode("NODENAME")
	s.mockNodes.EXPECT().Get(ctx, "NODENAME", metav1.GetOptions{}).Return(expectedNode, nil)

	client := s.createClient()
	node, err := client.GetNode(ctx, "NODENAME")
	s.NoError(err)
	s.Equal(expectedNode, node)
}

func (s *ClientSuite) TestValidateTokenFailsToLoadClient() {
	client := s.createDefectiveClient("")
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1", "aud2"})
	s.AssertErrorContains(err, "unable to get clientset")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenFailsIfGetsErrorFromAPIServer() {
	s.mockClientset.EXPECT().AuthenticationV1().Return(s.mockAuthV1).Times(1)
	s.mockAuthV1.EXPECT().TokenReviews().Return(s.mockTokenReviews).Times(1)
	req := createTokenReview([]string{"aud1"})
	s.mockTokenReviews.EXPECT().Create(ctx, req, metav1.CreateOptions{}).Return(nil, errors.New("an error"))

	client := s.createClient()
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.AssertErrorContains(err, "unable to query token review API")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenFailsIfGetsNilResponse() {
	s.mockClientset.EXPECT().AuthenticationV1().Return(s.mockAuthV1).Times(1)
	s.mockAuthV1.EXPECT().TokenReviews().Return(s.mockTokenReviews).Times(1)
	req := createTokenReview([]string{"aud1"})
	s.mockTokenReviews.EXPECT().Create(ctx, req, metav1.CreateOptions{}).Return(nil, nil)

	client := s.createClient()
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.AssertErrorContains(err, "token review API response is nil")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenFailsIfStatusContainsError() {
	s.mockClientset.EXPECT().AuthenticationV1().Return(s.mockAuthV1).Times(1)
	s.mockAuthV1.EXPECT().TokenReviews().Return(s.mockTokenReviews).Times(1)

	req := createTokenReview([]string{"aud1"})
	resp := *req
	resp.Status.Error = "an error"
	s.mockTokenReviews.EXPECT().Create(ctx, req, metav1.CreateOptions{}).Return(&resp, nil)

	client := s.createClient()
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.AssertErrorContains(err, "token review API response contains an error")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenSucceeds() {
	s.mockClientset.EXPECT().AuthenticationV1().Return(s.mockAuthV1).Times(1)
	s.mockAuthV1.EXPECT().TokenReviews().Return(s.mockTokenReviews).Times(1)

	req := createTokenReview([]string{"aud1"})
	resp := *req
	resp.Status.Authenticated = true
	s.mockTokenReviews.EXPECT().Create(ctx, req, metav1.CreateOptions{}).Return(&resp, nil)

	client := s.createClient()
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.NoError(err)
	s.NotNil(status)
	s.True(status.Authenticated)
}

func (s *ClientSuite) TestLoadClientFailsIfConfigCannotBeCreated() {
	kubeConfigPath := filepath.Join(s.dir, "not-valid-config-path")
	clientset, err := loadClient(kubeConfigPath)
	s.AssertErrorContains(err, "unable to create client config")
	s.Nil(clientset)
}

func (s *ClientSuite) TestLoadClientSucceds() {
	kubeConfigPath := filepath.Join(s.dir, "config")
	s.createSampleKubeConfigFile(kubeConfigPath)
	clientset, err := loadClient(kubeConfigPath)
	s.NoError(err)
	s.NotNil(clientset)
}

func (s *ClientSuite) createClient() Client {
	fakeLoadClient := func(kubeConfigFilePath string) (kubernetes.Interface, error) {
		return s.mockClientset, nil
	}
	return &client{
		loadClientHook: fakeLoadClient,
	}
}

func (s *ClientSuite) createDefectiveClient(kubeConfigFilePath string) Client {
	fakeLoadClient := func(kubeConfigFilePath string) (kubernetes.Interface, error) {
		return nil, errors.New("an error")
	}
	return &client{
		kubeConfigFilePath: kubeConfigFilePath,
		loadClientHook:     fakeLoadClient,
	}
}

func createPod(podName string) *v1.Pod {
	p := &v1.Pod{}
	p.Name = podName
	return p
}

func createNode(nodeName string) *v1.Node {
	n := &v1.Node{}
	n.Name = nodeName
	return n
}

func createTokenReview(audience []string) *authv1.TokenReview {
	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     testToken,
			Audiences: audience,
		},
	}
}

func (s *ClientSuite) createSampleKubeConfigFile(kubeConfigPath string) {
	caPath := filepath.Join(s.dir, "ca.crt")
	err := ioutil.WriteFile(caPath, kubeConfigCA, 0600)
	s.Require().NoError(err)

	clientCrtPath := filepath.Join(s.dir, "client.crt")
	err = ioutil.WriteFile(clientCrtPath, kubeConfigClientCert, 0600)
	s.Require().NoError(err)

	clientKeyPath := filepath.Join(s.dir, "client.key")
	err = ioutil.WriteFile(clientKeyPath, kubeConfigClientKey, 0600)
	s.Require().NoError(err)

	kubeConfigContent := []byte(fmt.Sprintf(kubeConfig, caPath, clientCrtPath, clientKeyPath))
	err = ioutil.WriteFile(kubeConfigPath, kubeConfigContent, 0600)
	s.Require().NoError(err)
}
