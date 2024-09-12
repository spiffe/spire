package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	pid = 123

	podListFilePath           = "testdata/pod_list.json"
	podListNotRunningFilePath = "testdata/pod_list_not_running.json"

	certPath = "cert.pem"
	keyPath  = "key.pem"
)

var (
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
	imageID          = "docker-pullable://localhost/spiffe/blog@sha256:0cfdaced91cb46dd7af48309799a3c351e4ca2d5e1ee9737ca0cbd932cb79898"
	testPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "node-name:k8s-node-1"},
		{Type: "k8s", Value: "ns:default"},
		{Type: "k8s", Value: "pod-image-count:2"},
		{Type: "k8s", Value: "pod-image:docker-pullable://localhost/spiffe/blog@sha256:0cfdaced91cb46dd7af48309799a3c351e4ca2d5e1ee9737ca0cbd932cb79898"},
		{Type: "k8s", Value: "pod-image:docker-pullable://localhost/spiffe/ghostunnel@sha256:b2fc20676c92a433b9a91f3f4535faddec0c2c3613849ac12f02c1d5cfcd4c3a"},
		{Type: "k8s", Value: "pod-image:localhost/spiffe/blog:latest"},
		{Type: "k8s", Value: "pod-image:localhost/spiffe/ghostunnel:latest"},
		{Type: "k8s", Value: "pod-init-image-count:0"},
		{Type: "k8s", Value: "pod-label:k8s-app:blog"},
		{Type: "k8s", Value: "pod-label:version:v0"},
		{Type: "k8s", Value: "pod-name:blog-24ck7"},
		{Type: "k8s", Value: "pod-owner-uid:ReplicationController:2c401175-b29f-11e7-9350-020968147796"},
		{Type: "k8s", Value: "pod-owner:ReplicationController:blog"},
		{Type: "k8s", Value: "pod-uid:2c48913c-b29f-11e7-9350-020968147796"},
		{Type: "k8s", Value: "sa:default"},
	}
	testContainerSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:docker-pullable://localhost/spiffe/blog@sha256:0cfdaced91cb46dd7af48309799a3c351e4ca2d5e1ee9737ca0cbd932cb79898"},
		{Type: "k8s", Value: "container-image:localhost/spiffe/blog:latest"},
		{Type: "k8s", Value: "container-name:blog"},
	}
	testPodAndContainerSelectors = append(testPodSelectors, testContainerSelectors...)

	sigstoreSelectors = []*common.Selector{
		{Type: "k8s", Value: "sigstore:selector"},
	}
)

type attestResult struct {
	selectors []*common.Selector
	err       error
}

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	dir   string
	clock *clock.Mock

	podList [][]byte
	env     map[string]string

	// kubelet stuff
	server      *httptest.Server
	kubeletCert *x509.Certificate
	clientCert  *x509.Certificate

	oc *osConfig
}

func (s *Suite) SetupTest() {
	s.dir = s.TempDir()
	s.writeFile(defaultTokenPath, "default-token")
	s.clock = clock.NewMock(s.T())
	s.server = nil
	s.podList = nil
	s.env = map[string]string{}

	s.oc = createOSConfig()
}

func (s *Suite) TearDownTest() {
	s.clock.Add(time.Minute)
	s.setServer(nil)
	os.RemoveAll(s.dir)
}

func (s *Suite) TestAttestWithPidInPod() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithPod(p)
}

func (s *Suite) TestAttestWithPidInPodAfterRetry() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListFilePath)
	s.addGetContainerResponsePidInPod()

	resultCh := s.goAttest(p)

	s.clock.WaitForAfter(time.Minute, "waiting for cache expiry timer")
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)

	select {
	case result := <-resultCh:
		s.Require().Nil(result.err)
		s.requireSelectorsEqual(testPodAndContainerSelectors, result.selectors)
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}
}

func (s *Suite) TestAttestWithPidNotInPodCancelsEarly() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.addPodListResponse(podListNotRunningFilePath)
	s.addGetContainerResponsePidInPod()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	selectors, err := p.Attest(ctx, pid)
	s.RequireGRPCStatus(err, codes.Canceled, "workloadattestor(k8s): context canceled")
	s.Require().Nil(selectors)
}

func (s *Suite) TestAttestPodListCache() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.addPodListResponse(podListFilePath)

	s.requireAttestSuccessWithPod(p)
	s.clock.WaitForAfter(time.Minute, "waiting for cache expiry timer")

	// The pod list is cached so we don't expect a request to kubelet
	s.requireAttestSuccessWithPod(p)

	// The cache expires after the clock advances by at least half the retry interval
	s.clock.Add(time.Minute)
	s.addPodListResponse(podListFilePath)
	s.requireAttestSuccessWithPod(p)
}

func (s *Suite) TestAttestWithPidNotInPodAfterRetry() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addGetContainerResponsePidInPod()

	resultCh := s.goAttest(p)

	s.clock.WaitForAfter(time.Minute, "waiting for cache expiry timer")
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)

	select {
	case result := <-resultCh:
		s.Require().Nil(result.selectors)
		s.RequireGRPCStatusContains(result.err, codes.DeadlineExceeded, "no selectors found after max poll attempts")
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}
}

func (s *Suite) TestAttestOverSecurePortViaTokenAuth() {
	// start up a secure kubelet with host networking and require token auth
	s.startSecureKubeletWithTokenAuth(true, "default-token")

	// use the service account token for auth
	p := s.loadSecurePlugin(``)

	s.requireAttestSuccessWithPod(p)

	// write out a different token and make sure it is picked up on reload
	s.writeFile(defaultTokenPath, "bad-token")
	s.clock.Add(defaultReloadInterval)
	s.requireAttestFailure(p, codes.Internal, `expected "Bearer default-token", got "Bearer bad-token"`)
}

func (s *Suite) TestAttestOverSecurePortViaClientAuth() {
	// start up the secure kubelet with host networking and require client certs
	s.startSecureKubeletWithClientCertAuth()

	// use client certificate for auth
	p := s.loadSecurePlugin(`
		certificate_path = "cert.pem"
		private_key_path = "key.pem"
	`)

	s.requireAttestSuccessWithPod(p)

	// write out a different client cert and make sure it is picked up on reload
	clientCert := s.createClientCert()
	s.writeCert(certPath, clientCert)

	s.clock.Add(defaultReloadInterval)
	s.requireAttestFailure(p, codes.Internal, "remote error: tls")
}

func (s *Suite) TestAttestOverSecurePortViaAnonymousAuth() {
	s.startSecureKubeletWithAnonymousAuth()

	p := s.loadSecurePlugin(`
		use_anonymous_authentication = true
	`)

	s.requireAttestSuccessWithPod(p)
}

func (s *Suite) TestAttestReachingKubeletViaNodeName() {
	// start up a secure kubelet with "localhost" certificate and token auth
	s.startSecureKubeletWithTokenAuth(false, "default-token")

	// pick up the node name from the default env value
	s.env["MY_NODE_NAME"] = "localhost"
	s.requireAttestSuccessWithPod(s.loadSecurePlugin(``))

	// pick up the node name from explicit config (should override env)
	s.env["MY_NODE_NAME"] = "bad-node-name"
	s.requireAttestSuccessWithPod(s.loadSecurePlugin(`
		node_name = "localhost"
	`))

	// pick up the node name from the overridden env value
	s.env["OVERRIDDEN_NODE_NAME"] = "localhost"
	s.requireAttestSuccessWithPod(s.loadSecurePlugin(`
		node_name_env = "OVERRIDDEN_NODE_NAME"
	`))
}

func (s *Suite) TestAttestWhenContainerReadyButContainerSelectorsDisabled() {
	s.startInsecureKubelet()
	p := s.loadInsecurePluginWithExtra("disable_container_selectors = true")
	s.addPodListResponse(podListFilePath)
	s.addGetContainerResponsePidInPod()
	s.requireAttestSuccess(p, testPodSelectors)
}

func (s *Suite) TestAttestWithSigstoreSelectors() {
	s.startInsecureKubelet()
	p := s.loadInsecurePluginWithSigstore()

	// Add the expected selectors from the Sigstore verifier
	testPodAndContainerSelectors = append(testPodAndContainerSelectors, sigstoreSelectors...)

	s.addPodListResponse(podListFilePath)
	s.addGetContainerResponsePidInPod()

	s.requireAttestSuccess(p, testPodAndContainerSelectors)
}

func (s *Suite) TestConfigure() {
	s.generateCerts("")

	kubeletCertPool := x509.NewCertPool()
	kubeletCertPool.AddCert(s.kubeletCert)

	s.writeFile(defaultTokenPath, "default-token")
	s.writeFile("token", "other-token")
	s.writeFile("bad-pem", "BAD PEM")
	s.writeCert("some-other-ca", s.kubeletCert)

	type config struct {
		Insecure          bool
		VerifyKubelet     bool
		HasNodeName       bool
		Token             string
		KubeletURL        string
		MaxPollAttempts   int
		PollRetryInterval time.Duration
		ReloadInterval    time.Duration
		SigstoreConfig    *sigstore.Config
	}

	testCases := []struct {
		name    string
		raw     string
		hcl     string
		config  *config
		errCode codes.Code
		errMsg  string
	}{
		{
			name: "insecure defaults",
			hcl: `
				kubelet_read_only_port = 12345
			`,
			config: &config{
				Insecure:          true,
				KubeletURL:        "http://127.0.0.1:12345",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
				ReloadInterval:    defaultReloadInterval,
			},
		},
		{
			name: "secure defaults",
			hcl:  ``,
			config: &config{
				VerifyKubelet:     true,
				Token:             "default-token",
				KubeletURL:        "https://127.0.0.1:10250",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
				ReloadInterval:    defaultReloadInterval,
			},
		},
		{
			name: "skip kubelet verification",
			hcl: `
				skip_kubelet_verification = true
			`,
			config: &config{
				VerifyKubelet:     false,
				Token:             "default-token",
				KubeletURL:        "https://127.0.0.1:10250",
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
				ReloadInterval:    defaultReloadInterval,
			},
		},
		{
			name: "secure overrides",
			hcl: `
				kubelet_secure_port = 12345
				kubelet_ca_path = "some-other-ca"
				token_path = "token"
				max_poll_attempts = 1
				poll_retry_interval = "2s"
				reload_interval = "3s"
			`,
			config: &config{
				VerifyKubelet:     true,
				Token:             "other-token",
				KubeletURL:        "https://127.0.0.1:12345",
				MaxPollAttempts:   1,
				PollRetryInterval: 2 * time.Second,
				ReloadInterval:    3 * time.Second,
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
				ReloadInterval:    defaultReloadInterval,
			},
		},
		{
			name: "secure with node name",
			hcl: `
				node_name = "boo"
			`,
			config: &config{
				VerifyKubelet:     true,
				KubeletURL:        "https://boo:10250",
				Token:             "default-token",
				HasNodeName:       true,
				MaxPollAttempts:   defaultMaxPollAttempts,
				PollRetryInterval: defaultPollRetryInterval,
				ReloadInterval:    defaultReloadInterval,
			},
		},

		{
			name:    "invalid hcl",
			hcl:     "bad",
			errCode: codes.InvalidArgument,
			errMsg:  "unable to decode configuration",
		},
		{
			name: "both insecure and secure ports specified",
			hcl: `
				kubelet_read_only_port = 10255
				kubelet_secure_port = 10250
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "cannot use both the read-only and secure port",
		},
		{
			name: "non-existent kubelet ca",
			hcl: `
				kubelet_ca_path = "no-such-file"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load kubelet CA",
		},
		{
			name: "bad kubelet ca",
			hcl: `
				kubelet_ca_path =  "bad-pem"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to parse kubelet CA",
		},
		{
			name: "non-existent token",
			hcl: `
				skip_kubelet_verification = true
				token_path = "no-such-file"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load token",
		},
		{
			name: "invalid poll retry interval",
			hcl: `
				kubelet_read_only_port = 10255
				poll_retry_interval = "blah"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to parse poll retry interval",
		},
		{
			name: "invalid reload interval",
			hcl: `
				kubelet_read_only_port = 10255
				reload_interval = "blah"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to parse reload interval",
		},
		{
			name: "cert but no key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "the private key path is required with the certificate path",
		},
		{
			name: "key but no cert",
			hcl: `
				skip_kubelet_verification = true
				private_key_path = "key"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "the certificate path is required with the private key path",
		},
		{
			name: "bad cert",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "bad-pem"
				private_key_path = "key.pem"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load keypair",
		},
		{
			name: "non-existent cert",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "no-such-file"
				private_key_path = "key.pem"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load certificate",
		},
		{
			name: "bad key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert.pem"
				private_key_path = "bad-pem"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load keypair",
		},
		{
			name: "non-existent key",
			hcl: `
				skip_kubelet_verification = true
				certificate_path = "cert.pem"
				private_key_path = "no-such-file"
			`,
			errCode: codes.InvalidArgument,
			errMsg:  "unable to load private key",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase // alias loop variable as it is used in the closure
		s.T().Run(testCase.name, func(t *testing.T) {
			p := s.newPlugin()

			var err error
			plugintest.Load(s.T(), builtin(p), nil,
				plugintest.Configure(testCase.hcl),
				plugintest.CaptureConfigureError(&err))

			if testCase.errMsg != "" {
				s.RequireGRPCStatusContains(err, testCase.errCode, testCase.errMsg)
				return
			}
			require.NotNil(t, testCase.config, "test case missing expected config")
			assert.NoError(t, err)

			c, _, _, err := p.getConfig()
			require.NoError(t, err)

			switch {
			case testCase.config.Insecure:
				assert.Nil(t, c.Client.Transport)
			case !assert.NotNil(t, c.Client.Transport):
			case !assert.NotNil(t, c.Client.Transport.TLSClientConfig):
			case !testCase.config.VerifyKubelet:
				assert.True(t, c.Client.Transport.TLSClientConfig.InsecureSkipVerify)
				assert.Nil(t, c.Client.Transport.TLSClientConfig.VerifyPeerCertificate)
			default:
				if testCase.config.HasNodeName {
					if assert.NotNil(t, c.Client.Transport.TLSClientConfig.RootCAs) {
						assert.True(t, c.Client.Transport.TLSClientConfig.RootCAs.Equal(kubeletCertPool))
					}
				} else {
					assert.True(t, c.Client.Transport.TLSClientConfig.InsecureSkipVerify)
					assert.NotNil(t, c.Client.Transport.TLSClientConfig.VerifyPeerCertificate)
				}
			}
			assert.Equal(t, testCase.config.Token, c.Client.Token)
			assert.Equal(t, testCase.config.KubeletURL, c.Client.URL.String())
			assert.Equal(t, testCase.config.MaxPollAttempts, c.MaxPollAttempts)
			assert.Equal(t, testCase.config.PollRetryInterval, c.PollRetryInterval)
			assert.Equal(t, testCase.config.ReloadInterval, c.ReloadInterval)
		})
	}
}

func (s *Suite) TestConfigureWithSigstore() {
	cases := []struct {
		name          string
		hcl           string
		expectedError string
		want          *sigstore.Config
	}{
		{
			name: "complete sigstore configuration",
			hcl: `
				    skip_kubelet_verification = true
					experimental {
    					sigstore {
        					allowed_identities = {
            					"test-issuer-1" = ["*@example.com", "subject@otherdomain.com"]
            					"test-issuer-2" = ["domain/ci.yaml@refs/tags/*"]
        					}
        					skipped_images = ["registry/image@sha256:examplehash"]
        					rekor_url = "https://test.dev"
        					ignore_sct = true
        					ignore_tlog = true
                            ignore_attestations = true
                            registry_credentials = {
                                "registry-1" = { username = "user1", password = "pass1" }
                                "registry-2" = { username = "user2", password = "pass2" }
                            }
    					}
			}`,
			expectedError: "",
		},
		{
			name: "empty sigstore configuration",
			hcl: `
				    skip_kubelet_verification = true
					experimental { sigstore {} }
			`,
			expectedError: "",
		},
		{
			name: "invalid HCL",
			hcl: `
				    skip_kubelet_verification = true
					experimental { sigstore = "invalid" }
			`,
			expectedError: "unable to decode configuration",
		},
	}

	for _, tc := range cases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			p := s.newPlugin()

			var err error
			plugintest.Load(s.T(), builtin(p), nil,
				plugintest.Configure(tc.hcl),
				plugintest.CaptureConfigureError(&err))

			if tc.expectedError != "" {
				s.RequireGRPCStatusContains(err, codes.InvalidArgument, tc.expectedError)
				return
			}
			require.NoError(t, err)

			_, _, sigstoreVerifier, err := p.getConfig()
			require.NoError(t, err)
			assert.NotNil(t, sigstoreVerifier)
		})
	}
}

func (s *Suite) newPlugin() *Plugin {
	p := New()
	p.rootDir = s.dir
	p.clock = s.clock
	p.getenv = func(key string) string {
		return s.env[key]
	}

	return p
}

func (s *Suite) setServer(server *httptest.Server) {
	if s.server != nil {
		s.server.Close()
	}
	s.server = server
}

func (s *Suite) writeFile(path, data string) {
	realPath := filepath.Join(s.dir, path)
	s.Require().NoError(os.MkdirAll(filepath.Dir(realPath), 0755))
	s.Require().NoError(os.WriteFile(realPath, []byte(data), 0600))
}

func (s *Suite) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	// TODO:
	if len(s.podList) == 0 {
		http.Error(w, "not configured to return a pod list", http.StatusOK)
		return
	}
	podList := s.podList[0]
	s.podList = s.podList[1:]
	_, _ = w.Write(podList)
}

func (s *Suite) kubeletPort() int {
	s.Require().NotNil(s.server, "kubelet must be started first")
	tcpAddr, ok := s.server.Listener.Addr().(*net.TCPAddr)
	s.Require().True(ok, "server not listening on TCP")
	return tcpAddr.Port
}

func (s *Suite) loadPlugin(configuration string) workloadattestor.WorkloadAttestor {
	v1 := new(workloadattestor.V1)
	p := s.newPlugin()

	plugintest.Load(s.T(), builtin(p), v1,
		plugintest.Configure(configuration),
	)

	if cHelper := s.oc.getContainerHelper(p); cHelper != nil {
		p.setContainerHelper(cHelper)
	}

	// if sigstore is configured, override with fake
	if p.sigstoreVerifier != nil {
		p.sigstoreVerifier = newFakeSigstoreVerifier(map[string][]string{imageID: {"sigstore:selector"}})
	}
	return v1
}

func (s *Suite) loadInsecurePlugin() workloadattestor.WorkloadAttestor {
	return s.loadPlugin(fmt.Sprintf(`
		kubelet_read_only_port = %d
		max_poll_attempts = 5
		poll_retry_interval = "1s"
`, s.kubeletPort()))
}

func (s *Suite) loadInsecurePluginWithExtra(extraConfig string) workloadattestor.WorkloadAttestor {
	return s.loadPlugin(fmt.Sprintf(`
		kubelet_read_only_port = %d
		max_poll_attempts = 5
		poll_retry_interval = "1s"
		%s
`, s.kubeletPort(), extraConfig))
}

func (s *Suite) loadInsecurePluginWithSigstore() workloadattestor.WorkloadAttestor {
	return s.loadPlugin(fmt.Sprintf(`
		kubelet_read_only_port = %d
		max_poll_attempts = 5
		poll_retry_interval = "1s"
		experimental {
			sigstore {
			}
		}
	`, s.kubeletPort()))
}

func (s *Suite) startInsecureKubelet() {
	s.setServer(httptest.NewServer(http.HandlerFunc(s.serveHTTP)))
}

func (s *Suite) generateCerts(nodeName string) {
	s.kubeletCert = s.createKubeletCert(nodeName)
	s.writeCert(defaultKubeletCAPath, s.kubeletCert)

	s.clientCert = s.createClientCert()
	s.writeKey(keyPath, clientKey)
	s.writeCert(certPath, s.clientCert)
}

func (s *Suite) startSecureKubeletWithClientCertAuth() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.VerifiedChains) == 0 {
			http.Error(w, "client auth expected but not used", http.StatusForbidden)
			return
		}
		s.serveHTTP(w, req)
	})

	s.startSecureKubeletServer(false, handler)
}

func (s *Suite) startSecureKubeletWithTokenAuth(hostNetworking bool, token string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
		s.serveHTTP(w, req)
	})

	s.startSecureKubeletServer(hostNetworking, handler)
}

func (s *Suite) startSecureKubeletWithAnonymousAuth() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.VerifiedChains) > 0 {
			http.Error(w, "client auth not expected but used", http.StatusForbidden)
			return
		}
		s.serveHTTP(w, req)
	})

	s.startSecureKubeletServer(false, handler)
}

func (s *Suite) startSecureKubeletServer(hostNetworking bool, handler http.Handler) {
	// Use "localhost" in the DNS name unless we're using host networking. This
	// allows us to use "localhost" as the host directly when configured to
	// connect to the node name. Otherwise, we'll connect to 127.0.0.1 and
	// bypass server name verification.
	dnsName := "localhost"
	if hostNetworking {
		dnsName = "this-name-should-never-be-validated"
	}

	s.generateCerts(dnsName)
	clientCAs := x509.NewCertPool()
	if s.clientCert != nil {
		clientCAs.AddCert(s.clientCert)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{s.kubeletCert.Raw},
				PrivateKey:  kubeletKey,
			},
		},
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	s.setServer(server)
}

func (s *Suite) loadSecurePlugin(extraConfig string) workloadattestor.WorkloadAttestor {
	return s.loadPlugin(fmt.Sprintf(`
		kubelet_secure_port = %d
		%s
	`, s.kubeletPort(), extraConfig))
}

func (s *Suite) createKubeletCert(dnsName string) *x509.Certificate {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     now.Add(time.Minute),
		Subject: pkix.Name{
			CommonName: "whoknows",
		},
		DNSNames: []string{dnsName},
	}
	return s.createCert(tmpl, kubeletKey)
}

func (s *Suite) createClientCert() *x509.Certificate {
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

func (s *Suite) createCert(tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)
	return cert
}

func (s *Suite) writeCert(path string, cert *x509.Certificate) {
	s.writeFile(path, string(pemutil.EncodeCertificate(cert)))
}

func (s *Suite) writeKey(path string, key *ecdsa.PrivateKey) {
	pemBytes, err := pemutil.EncodePKCS8PrivateKey(key)
	s.Require().NoError(err)
	s.writeFile(path, string(pemBytes))
}

func (s *Suite) requireAttestSuccessWithPod(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(podListFilePath)
	s.addGetContainerResponsePidInPod()
	s.requireAttestSuccess(p, testPodAndContainerSelectors)
}

func (s *Suite) requireAttestSuccess(p workloadattestor.WorkloadAttestor, expectedSelectors []*common.Selector) {
	selectors, err := p.Attest(context.Background(), pid)
	s.Require().NoError(err)
	s.requireSelectorsEqual(expectedSelectors, selectors)
}

func (s *Suite) requireAttestFailure(p workloadattestor.WorkloadAttestor, code codes.Code, contains string) {
	selectors, err := p.Attest(context.Background(), pid)
	s.RequireGRPCStatusContains(err, code, contains)
	s.Require().Nil(selectors)
}

func (s *Suite) requireSelectorsEqual(expected, actual []*common.Selector) {
	// assert the selectors (non-destructively sorting for consistency)
	actual = append([]*common.Selector(nil), actual...)
	expected = append([]*common.Selector(nil), expected...)
	util.SortSelectors(actual)
	util.SortSelectors(expected)
	s.RequireProtoListEqual(expected, actual)
}

func (s *Suite) goAttest(p workloadattestor.WorkloadAttestor) <-chan attestResult {
	resultCh := make(chan attestResult, 1)
	go func() {
		selectors, err := p.Attest(context.Background(), pid)
		resultCh <- attestResult{
			selectors: selectors,
			err:       err,
		}
	}()
	return resultCh
}

func (s *Suite) addPodListResponse(fixturePath string) {
	podList, err := os.ReadFile(fixturePath)
	s.Require().NoError(err)

	s.podList = append(s.podList, podList)
}

type fakeSigstoreVerifier struct {
	mu sync.Mutex

	SigDetailsSets map[string][]string
}

func newFakeSigstoreVerifier(selectors map[string][]string) *fakeSigstoreVerifier {
	return &fakeSigstoreVerifier{
		SigDetailsSets: selectors,
	}
}

func (v *fakeSigstoreVerifier) Verify(_ context.Context, imageID string) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if selectors, found := v.SigDetailsSets[imageID]; found {
		return selectors, nil
	}

	return nil, fmt.Errorf("failed to verify signature for image %s", imageID)
}
