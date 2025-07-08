package apiserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	fake_authv1 "k8s.io/client-go/kubernetes/typed/authentication/v1/fake"
	fake_corev1 "k8s.io/client-go/kubernetes/typed/core/v1/fake"
	k8stesting "k8s.io/client-go/testing"
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

	wantAudiences = []string{"aud1", "aud2"}
)

const (
	testToken = "TEST-TOKEN"
)

func TestAPIServerClient(t *testing.T) {
	spiretest.Run(t, new(ClientSuite))
}

type ClientSuite struct {
	spiretest.Suite
	dir string
}

func (s *ClientSuite) SetupTest() {
	s.dir = s.TempDir()
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
	fakeClient := fake.NewClientset()

	client := s.createClient(fakeClient)
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.AssertErrorContains(err, "unable to query pods API")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodIsEmptyIfGetsNilPod() {
	fakeClient := fake.NewClientset()
	fakeClient.CoreV1().(*fake_corev1.FakeCoreV1).PrependReactor("get", "pods",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, nil
		})

	client := s.createClient(fakeClient)
	pod, err := client.GetPod(ctx, "NAMESPACE", "PODNAME")
	s.NoError(err)
	s.Require().Empty(pod)
}

func (s *ClientSuite) TestGetPodSucceeds() {
	fakeClient := fake.NewClientset(createPod("PODNAME", "NAMESPACE"))
	expectedPod := createPod("PODNAME", "NAMESPACE")

	client := s.createClient(fakeClient)
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
	fakeClient := fake.NewClientset()

	client := s.createClient(fakeClient)
	node, err := client.GetNode(ctx, "NODENAME")
	s.AssertErrorContains(err, "unable to query nodes API")
	s.Nil(node)
}

func (s *ClientSuite) TestGetNodeIsEmptyIfGetsNilNode() {
	fakeClient := fake.NewClientset()
	fakeClient.CoreV1().(*fake_corev1.FakeCoreV1).PrependReactor("get", "nodes",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, nil
		})

	client := s.createClient(fakeClient)
	node, err := client.GetNode(ctx, "NODENAME")
	s.Require().NoError(err)
	s.Require().Empty(node)
}

func (s *ClientSuite) TestGetNodeSucceeds() {
	fakeClient := fake.NewClientset(createNode("NODENAME"))
	expectedNode := createNode("NODENAME")

	client := s.createClient(fakeClient)
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
	fakeClient := fake.NewClientset()
	fakeClient.AuthenticationV1().(*fake_authv1.FakeAuthenticationV1).PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &authv1.TokenReview{}, errors.New("error creating token review")
		})

	client := s.createClient(fakeClient)
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.AssertErrorContains(err, "unable to query token review API")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenIsEmptyIfGetsNilResponse() {
	fakeClient := fake.NewClientset()
	fakeClient.AuthenticationV1().(*fake_authv1.FakeAuthenticationV1).PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, nil
		})

	client := s.createClient(fakeClient)
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.Require().NoError(err)
	s.Require().Empty(status)
}

func (s *ClientSuite) TestValidateTokenFailsIfStatusContainsError() {
	fakeClient := fake.NewClientset()
	fakeClient.AuthenticationV1().(*fake_authv1.FakeAuthenticationV1).PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Error: "an error"}}, nil
		})

	client := s.createClient(fakeClient)
	status, err := client.ValidateToken(ctx, testToken, []string{"aud1"})
	s.AssertErrorContains(err, "token review API response contains an error")
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenFailsDueToAudienceUnawareValidator() {
	fakeClient := fake.NewClientset()
	fakeClient.AuthenticationV1().(*fake_authv1.FakeAuthenticationV1).PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"aud3"},
				},
			}, nil
		})

	client := s.createClient(fakeClient)
	status, err := client.ValidateToken(ctx, testToken, wantAudiences)
	s.AssertErrorContains(err, `token review API did not validate audience: wanted one of ["aud1" "aud2"] but got ["aud3"]`)
	s.Nil(status)
}

func (s *ClientSuite) TestValidateTokenSucceeds() {
	fakeClient := fake.NewClientset()
	fakeClient.AuthenticationV1().(*fake_authv1.FakeAuthenticationV1).PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     wantAudiences[:1],
				},
			}, nil
		})

	client := s.createClient(fakeClient)
	status, err := client.ValidateToken(ctx, testToken, wantAudiences)
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

func (s *ClientSuite) TestLoadClientSucceeds() {
	kubeConfigPath := filepath.Join(s.dir, "config")
	s.createSampleKubeConfigFile(kubeConfigPath)
	clientset, err := loadClient(kubeConfigPath)
	s.NoError(err)
	s.NotNil(clientset)
}

func (s *ClientSuite) createClient(fakeClient kubernetes.Interface) Client {
	fakeLoadClient := func(kubeConfigFilePath string) (kubernetes.Interface, error) {
		return fakeClient, nil
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

func createPod(podName, namespace string) *v1.Pod {
	p := &v1.Pod{}
	p.Name = podName
	p.Namespace = namespace
	return p
}

func createNode(nodeName string) *v1.Node {
	n := &v1.Node{}
	n.Name = nodeName
	return n
}

func (s *ClientSuite) createSampleKubeConfigFile(kubeConfigPath string) {
	caPath := filepath.Join(s.dir, "ca.crt")
	err := os.WriteFile(caPath, kubeConfigCA, 0o600)
	s.Require().NoError(err)

	clientCrtPath := filepath.Join(s.dir, "client.crt")
	err = os.WriteFile(clientCrtPath, kubeConfigClientCert, 0o600)
	s.Require().NoError(err)

	clientKeyPath := filepath.Join(s.dir, "client.key")
	err = os.WriteFile(clientKeyPath, kubeConfigClientKey, 0o600)
	s.Require().NoError(err)

	kubeConfigContent := fmt.Appendf(nil, kubeConfig, caPath, clientCrtPath, clientKeyPath)
	err = os.WriteFile(kubeConfigPath, kubeConfigContent, 0o600)
	s.Require().NoError(err)
}
