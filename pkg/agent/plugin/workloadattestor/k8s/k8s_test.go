package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	pid                       = 123
	podListFilePath           = "testdata/pod_list.json"
	podListNotRunningFilePath = "testdata/pod_list_not_running.json"
	cgPidInPodFilePath        = "testdata/cgroups_pid_in_pod.txt"
	cgInitPidInPodFilePath    = "testdata/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath     = "testdata/cgroups_pid_not_in_pod.txt"

	kubeletCAPath = "kubelet-ca.pem"
	certPath      = "cert.pem"
	keyPath       = "key.pem"
)

type attestResult struct {
	resp *workloadattestor.AttestResponse
	err  error
}

var (
	pidCgroupPath = fmt.Sprintf("/proc/%v/cgroup", pid)

	clientKey, _ = pemutil.ParseECPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNRa/6HIy0uwQe8iG
Kz24zEvwGiIsTDPHzrLUaml1hQ6hRANCAATz6vtJYIvPM0KOqKpdDPlsOw09hZ8P
Smpe/sa+wRV0Nt8c39deep4bl+GKUuptzv998wSl6vI/NYnZW9rGbxMU
-----END PRIVATE KEY-----
`))

	kubeletKey, _ = pemutil.ParseECPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWjgGFx4zuQMXcXrk
AyIlgLJ/QQypapKXYPr4kLuFWFShRANCAARFfHk9kz/bGtZfcIhJpzvnSnKbSvuK
FwOGLt+I3+9beT0vo+pn9Rq0squewFYe3aJbwpkyfP2xOovQCdm4PC8y
-----END PRIVATE KEY-----
`))
)

func TestK8sAttestor(t *testing.T) {
	suite.Run(t, new(K8sAttestorSuite))
}

type K8sAttestorSuite struct {
	suite.Suite

	dir    string
	clock  *clock.Mock
	server *httptest.Server
	p      *k8sPlugin

	podList [][]byte
}

func (s *K8sAttestorSuite) SetupTest() {
	dir, err := ioutil.TempDir("", "k8s-workloadattestor-test")
	s.Require().NoError(err)
	s.dir = dir

	s.clock = clock.NewMock(s.T())
	s.server = nil

	s.p = s.newPlugin()
	s.podList = nil
}

func (s *K8sAttestorSuite) TearDownTest() {
	s.setServer(nil)
	os.RemoveAll(s.dir)
}

func (s *K8sAttestorSuite) TestAttestWithPidInPod() {
	s.configureInsecure()
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithPidInPodOverSecurePort() {
	s.writeFile(defaultTokenPath, "default-token")
	s.configureSecure("default-token")
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithPidInPodOverSecurePortWithClientAuth() {
	s.configureSecure("")
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithInitPidInPod() {
	s.configureInsecure()
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgInitPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithPidInPodAfterRetry() {
	s.configureInsecure()
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resultCh := s.goAttest()

	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)

	select {
	case result := <-resultCh:
		s.Require().Nil(result.err)
		// assert the selectors (sorting for consistency)
		util.SortSelectors(result.resp.Selectors)
		s.Require().Equal([]*common.Selector{
			{Type: "k8s", Value: "container-image:localhost/spiffe/blog:latest"},
			{Type: "k8s", Value: "container-name:blog"},
			{Type: "k8s", Value: "node-name:k8s-node-1"},
			{Type: "k8s", Value: "ns:default"},
			{Type: "k8s", Value: "pod-label:k8s-app:blog"},
			{Type: "k8s", Value: "pod-label:version:v0"},
			{Type: "k8s", Value: "pod-owner-uid:ReplicationController:2c401175-b29f-11e7-9350-020968147796"},
			{Type: "k8s", Value: "pod-owner:ReplicationController:blog"},
			{Type: "k8s", Value: "pod-uid:2c48913c-b29f-11e7-9350-020968147796"},
			{Type: "k8s", Value: "sa:default"},
		}, result.resp.Selectors)
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}

}

func (s *K8sAttestorSuite) TestAttestWithPidNotInPodCancelsEarly() {
	s.configureInsecure()
	s.addPodListResponse(podListNotRunningFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := s.p.Attest(ctx, &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "k8s: no selectors found: context canceled")
	s.Require().Nil(resp)
}

func (s *K8sAttestorSuite) TestAttestWithPidNotInPodAfterRetry() {
	s.configureInsecure()
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resultCh := s.goAttest()

	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(defaultPollRetryInterval)

	select {
	case result := <-resultCh:
		s.Require().Nil(result.resp)
		s.Require().Error(result.err)
		s.Require().Contains(result.err.Error(), "k8s: no selectors found")
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}
}

func (s *K8sAttestorSuite) TestAttestWithPidNotInPod() {
	s.configureInsecure()
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().Empty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestConfigure() {
	// this test doesn't need the server but does need all of the certs/keys
	// that are written to disk.
	s.startSecureServer("")

	s.writeFile(defaultTokenPath, "default-token")
	s.writeFile("token", "other-token")
	s.writeFile("bad-pem", "BAD PEM")

	type config struct {
		NoTLS             bool
		VerifyKubelet     bool
		Token             string
		KubeletURL        string
		MaxPollAttempts   int
		PollRetryInterval time.Duration
	}

	testCases := []struct {
		name   string
		raw    string
		hcl    string
		config *config
		err    string
	}{
		{
			name: "insecure defaults",
			hcl: `
				kubelet_read_only_port = 12345
			`,
			config: &config{
				NoTLS:             true,
				KubeletURL:        "http://127.0.0.1:12345",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
			},
		},
		{
			name: "secure defaults",
			hcl: `
				kubelet_ca_path = "kubelet-ca.pem"
			`,
			config: &config{
				VerifyKubelet:     true,
				Token:             "default-token",
				KubeletURL:        "https://127.0.0.1:10250",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
			},
		},
		{
			name: "secure overrides and skipping kubelet verification",
			hcl: `
				kubelet_secure_port = 12345
				skip_kubelet_verification = true
				token_path = "token"
				max_poll_attempts = 1
				poll_retry_interval = "2s"
			`,
			config: &config{
				Token:             "other-token",
				KubeletURL:        "https://127.0.0.1:12345",
				MaxPollAttempts:   1,
				PollRetryInterval: 2 * time.Second,
			},
		},
		{
			name: "secure with keypair",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert.pem"
				private_key_path = "key.pem"
			`,
			config: &config{
				KubeletURL:        "https://127.0.0.1:10250",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
			},
		},
		{
			name: "invalid hcl",
			hcl:  "bad",
			err:  "unable to decode configuration",
		},
		{
			name: "both insecure and secure ports specified",
			hcl: `
				kubelet_read_only_port = 10255
				kubelet_secure_port = 10250
			`,
			err: "cannot use both the read-only and secure port",
		},
		{
			name: "no kubelet ca path",
			hcl:  ``,
			err:  "kubelet CA path is required",
		},
		{
			name: "non-existant kubelet ca",
			hcl: `
				kubelet_ca_path = "no-such-file"
			`,
			err: "unable to load kubelet CA",
		},
		{
			name: "bad kubelet ca",
			hcl: `
				kubelet_ca_path =  "bad-pem"
			`,
			err: "unable to parse kubelet CA",
		},
		{
			name: "non-existant token",
			hcl: `
				skip_kubelet_verification = true
				token_path = "no-such-file"
			`,
			err: "unable to load token",
		},
		{
			name: "invalid poll retry interval",
			hcl: `
				kubelet_read_only_port = 10255
				poll_retry_interval = "blah"
			`,
			err: "unable to parse poll retry interval",
		},
		{
			name: "cert but no key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert"
			`,
			err: "the private key path is required with the certificate path",
		},
		{
			name: "key but no cert",
			hcl: `
				skip_kubelet_verification = true
				private_key_path = "key"
			`,
			err: "the certificate path is required with the private key path",
		},
		{
			name: "bad cert",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "bad-pem"
				private_key_path = "key.pem"
			`,
			err: "unable to load keypair",
		},
		{
			name: "non-existent cert",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "no-such-file"
				private_key_path = "key.pem"
			`,
			err: "unable to load certificate",
		},
		{
			name: "bad key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert.pem"
				private_key_path = "bad-pem"
			`,
			err: "unable to load keypair",
		},
		{
			name: "non-existent key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert.pem"
				private_key_path = "no-such-file"
			`,
			err: "unable to load private key",
		},
	}

	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			p := s.newPlugin()
			resp, err := p.Configure(context.Background(), &spi.ConfigureRequest{
				Configuration: testCase.hcl,
			})
			if testCase.err != "" {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), testCase.err)
				}
				return
			}
			require.NotNil(t, testCase.config, "test case missing expected config")

			assert.NoError(t, err)
			assert.Equal(t, &spi.ConfigureResponse{}, resp)

			c, err := p.getConfig()
			require.NoError(t, err)

			switch {
			case !assert.NotNil(t, c.Transport):
			case testCase.config.NoTLS:
				assert.Nil(t, c.Transport.TLSClientConfig)
			case !assert.NotNil(t, c.Transport.TLSClientConfig):
			case !testCase.config.VerifyKubelet:
			case !assert.NotNil(t, c.Transport.TLSClientConfig.RootCAs):
			default:
				assert.Len(t, c.Transport.TLSClientConfig.RootCAs.Subjects(), 1)
			}
			assert.Equal(t, testCase.config.Token, c.Token)
			assert.Equal(t, testCase.config.KubeletURL, c.KubeletURL.String())
			assert.Equal(t, testCase.config.MaxPollAttempts, c.MaxPollAttempts)
			assert.Equal(t, testCase.config.PollRetryInterval, c.PollRetryInterval)
		})
	}
}

func (s *K8sAttestorSuite) TestGetPluginInfo() {
	resp, err := s.p.GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	s.NoError(err)
	s.Equal(&spi.GetPluginInfoResponse{}, resp)
}

func (s *K8sAttestorSuite) newPlugin() *k8sPlugin {
	p := New()
	p.fs = testFS(s.dir)
	p.clock = s.clock
	p.getenv = func(key string) string {
		if key == "HOSTNAME" {
			return "kubelethost"
		}
		return os.Getenv(key)
	}
	return p
}

func (s *K8sAttestorSuite) setServer(server *httptest.Server) {
	if s.server != nil {
		s.server.Close()
	}
	s.server = server
}

func (s *K8sAttestorSuite) writeFile(path, data string) {
	realPath := filepath.Join(s.dir, path)
	s.Require().NoError(os.MkdirAll(filepath.Dir(realPath), 0755))
	s.Require().NoError(ioutil.WriteFile(realPath, []byte(data), 0644))
}

func (s *K8sAttestorSuite) serveHTTP(w http.ResponseWriter, req *http.Request) {
	// TODO:
	if len(s.podList) == 0 {
		http.Error(w, "not configured to return a pod list", http.StatusOK)
		return
	}
	podList := s.podList[0]
	s.podList = s.podList[1:]
	w.Write(podList)
}

func (s *K8sAttestorSuite) configureInsecure() {
	s.startInsecureServer()

	configuration := fmt.Sprintf(`
		kubelet_read_only_port = %d
`, s.server.Listener.Addr().(*net.TCPAddr).Port)

	_, err := s.p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	s.Require().NoError(err)
}

func (s *K8sAttestorSuite) startInsecureServer() {
	s.setServer(httptest.NewServer(http.HandlerFunc(s.serveHTTP)))
}

func (s *K8sAttestorSuite) configureSecure(token string) {
	s.startSecureServer(token)

	configuration := fmt.Sprintf(`
		kubelet_secure_port = %d
		kubelet_ca_path = %q
`, s.server.Listener.Addr().(*net.TCPAddr).Port, kubeletCAPath)

	if token == "" {
		configuration += fmt.Sprintf(`
		certificate_path = %q
		private_key_path = %q
`, certPath, keyPath)
	}

	_, err := s.p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	s.Require().NoError(err)
}

func (s *K8sAttestorSuite) startSecureServer(token string) {
	kubeletCert := s.createKubeletCert()
	s.writeCert(kubeletCAPath, kubeletCert)

	clientCert := s.createClientCert()
	s.writeKey(keyPath, clientKey)
	s.writeCert(certPath, clientCert)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCert)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if token == "" {
			if len(req.TLS.VerifiedChains) == 0 {
				http.Error(w, "client auth expected but not used", http.StatusForbidden)
				return
			}
		} else {
			if len(req.TLS.VerifiedChains) > 0 {
				http.Error(w, "client auth not expected but used", http.StatusForbidden)
				return
			}
			expectedAuth := "Bearer " + token
			auth := req.Header.Get("Authorization")
			if auth != expectedAuth {
				http.Error(w, fmt.Sprintf("expected %q, got %q", expectedAuth, auth), http.StatusForbidden)
				return
			}
		}
		s.serveHTTP(w, req)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{kubeletCert.Raw},
				PrivateKey:  kubeletKey,
			},
		},
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}
	server.StartTLS()
	s.setServer(server)
}

func (s *K8sAttestorSuite) createKubeletCert() *x509.Certificate {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     now.Add(time.Minute),
		Subject: pkix.Name{
			CommonName: "whoknows",
		},
		DNSNames: []string{"kubelethost"},
	}
	return s.createCert(tmpl, kubeletKey)
}

func (s *K8sAttestorSuite) createClientCert() *x509.Certificate {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     now.Add(time.Minute),
		Subject: pkix.Name{
			CommonName: "CLIENT",
		},
	}
	return s.createCert(tmpl, clientKey)
}

func (s *K8sAttestorSuite) createCert(tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)
	return cert
}

func (s *K8sAttestorSuite) writeCert(path string, cert *x509.Certificate) {
	s.writeFile(path, string(pemutil.EncodeCertificate(cert)))
}

func (s *K8sAttestorSuite) writeKey(path string, key *ecdsa.PrivateKey) {
	pemBytes, err := pemutil.EncodePKCS8PrivateKey(key)
	s.Require().NoError(err)
	s.writeFile(keyPath, string(pemBytes))
}

func (s *K8sAttestorSuite) goAttest() <-chan attestResult {
	resultCh := make(chan attestResult, 1)
	go func() {
		resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
			Pid: int32(pid),
		})
		resultCh <- attestResult{
			resp: resp,
			err:  err,
		}
	}()
	return resultCh
}

func (s *K8sAttestorSuite) addPodListResponse(fixturePath string) {
	podList, err := ioutil.ReadFile(fixturePath)
	s.Require().NoError(err)

	s.podList = append(s.podList, podList)
}

func (s *K8sAttestorSuite) addCgroupsResponse(fixturePath string) {
	wd, err := os.Getwd()
	s.Require().NoError(err)
	cgroupPath := filepath.Join(s.dir, pidCgroupPath)
	s.Require().NoError(os.MkdirAll(filepath.Dir(cgroupPath), 0755))
	s.Require().NoError(os.Symlink(filepath.Join(wd, fixturePath), cgroupPath))
}

type testFS string

func (fs testFS) Open(path string) (*os.File, error) {
	return os.Open(filepath.Join(string(fs), path))
}
