package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	pid = 123

	podListFilePath           = "testdata/pod_list.json"
	kindPodListFilePath       = "testdata/kind_pod_list.json"
	podListNotRunningFilePath = "testdata/pod_list_not_running.json"

	cgPidInPodFilePath        = "testdata/cgroups_pid_in_pod.txt"
	cgPidInKindPodFilePath    = "testdata/cgroups_pid_in_kind_pod.txt"
	cgInitPidInPodFilePath    = "testdata/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath     = "testdata/cgroups_pid_not_in_pod.txt"
	cgSystemdPidInPodFilePath = "testdata/systemd_cgroups_pid_in_pod.txt"

	certPath = "cert.pem"
	keyPath  = "key.pem"
)

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

	testPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:docker-pullable://localhost/spiffe/blog@sha256:0cfdaced91cb46dd7af48309799a3c351e4ca2d5e1ee9737ca0cbd932cb79898"},
		{Type: "k8s", Value: "container-image:localhost/spiffe/blog:latest"},
		{Type: "k8s", Value: "container-name:blog"},
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

	testKindPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "container-name:workload-api-client"},
		{Type: "k8s", Value: "node-name:kind-control-plane"},
		{Type: "k8s", Value: "ns:default"},
		{Type: "k8s", Value: "pod-image-count:1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "pod-init-image-count:0"},
		{Type: "k8s", Value: "pod-label:app:sample-workload"},
		{Type: "k8s", Value: "pod-label:pod-template-hash:6658cb9566"},
		{Type: "k8s", Value: "pod-name:sample-workload-6658cb9566-5n4b4"},
		{Type: "k8s", Value: "pod-owner-uid:ReplicaSet:349d135e-3781-43e3-bc25-c900aedf1d0c"},
		{Type: "k8s", Value: "pod-owner:ReplicaSet:sample-workload-6658cb9566"},
		{Type: "k8s", Value: "pod-uid:a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80"},
		{Type: "k8s", Value: "sa:default"},
	}

	testInitPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "container-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "container-name:install-cni"},
		{Type: "k8s", Value: "node-name:k8s-node-1"},
		{Type: "k8s", Value: "ns:kube-system"},
		{Type: "k8s", Value: "pod-image-count:1"},
		{Type: "k8s", Value: "pod-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "pod-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "pod-init-image-count:1"},
		{Type: "k8s", Value: "pod-init-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "pod-init-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "pod-label:app:flannel"},
		{Type: "k8s", Value: "pod-label:controller-revision-hash:1846323910"},
		{Type: "k8s", Value: "pod-label:pod-template-generation:1"},
		{Type: "k8s", Value: "pod-label:tier:node"},
		{Type: "k8s", Value: "pod-name:kube-flannel-ds-gp1g9"},
		{Type: "k8s", Value: "pod-owner-uid:DaemonSet:2f0350fc-b29d-11e7-9350-020968147796"},
		{Type: "k8s", Value: "pod-owner:DaemonSet:kube-flannel-ds"},
		{Type: "k8s", Value: "pod-uid:d488cae9-b2a0-11e7-9350-020968147796"},
		{Type: "k8s", Value: "sa:flannel"},
	}
)

type attestResult struct {
	resp *workloadattestor.AttestResponse
	err  error
}

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	dir   string
	clock *clock.Mock
	p     workloadattestor.Plugin

	podList [][]byte
	env     map[string]string

	// kubelet stuff
	server      *httptest.Server
	kubeletCert *x509.Certificate
	clientCert  *x509.Certificate
}

func (s *Suite) SetupTest() {
	s.dir = s.TempDir()
	s.writeFile(defaultTokenPath, "default-token")

	s.clock = clock.NewMock(s.T())
	s.server = nil

	_, s.p = s.newPlugin()
	s.podList = nil
	s.env = map[string]string{}
}

func (s *Suite) TearDownTest() {
	s.setServer(nil)
	os.RemoveAll(s.dir)
}

func (s *Suite) TestAttestWithPidInPod() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.requireAttestSuccessWithPod()
}

func (s *Suite) TestAttestWithPidInKindPod() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.requireAttestSuccessWithKindPod()
}

func (s *Suite) TestAttestWithPidInPodSystemdCgroups() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.requireAttestSuccessWithPodSystemdCgroups()
}

func (s *Suite) TestAttestWithInitPidInPod() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.requireAttestSuccessWithInitPod()
}

func (s *Suite) TestAttestWithPidInPodAfterRetry() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resultCh := s.goAttest()

	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)
	s.clock.WaitForAfter(time.Minute, "waiting for retry timer")
	s.clock.Add(time.Second)

	select {
	case result := <-resultCh:
		s.Require().Nil(result.err)
		s.requireSelectorsEqual(testPodSelectors, result.resp.Selectors)
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}
}

func (s *Suite) TestAttestWithPidNotInPodCancelsEarly() {
	s.startInsecureKubelet()
	s.configureInsecure()

	s.addPodListResponse(podListNotRunningFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := s.p.Attest(ctx, &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.RequireGRPCStatus(err, codes.Canceled, "context canceled")
	s.Require().Nil(resp)
}

func (s *Suite) TestAttestWithPidNotInPodAfterRetry() {
	s.startInsecureKubelet()
	s.configureInsecure()
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resultCh := s.goAttest()

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
		s.Require().Nil(result.resp)
		s.RequireErrorContains(result.err, "k8s: no selectors found")
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for attest response")
	}
}

func (s *Suite) TestAttestWithPidNotInPod() {
	s.startInsecureKubelet()
	s.configureInsecure()
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().Empty(resp.Selectors)
}

func (s *Suite) TestAttestOverSecurePortViaTokenAuth() {
	// start up a secure kubelet with host networking and require token auth
	s.startSecureKubelet(true, "default-token")

	// use the service account token for auth
	s.configureSecure(``)

	s.requireAttestSuccessWithPod()

	// write out a different token and make sure it is picked up on reload
	s.writeFile(defaultTokenPath, "bad-token")
	s.clock.Add(defaultReloadInterval)
	s.requireAttestFailure(`expected "Bearer default-token", got "Bearer bad-token"`)
}

func (s *Suite) TestAttestOverSecurePortViaClientAuth() {
	// start up the secure kubelet with host networking and require client certs
	s.startSecureKubelet(true, "")

	// use client certificate for auth
	s.configureSecure(`
		certificate_path = "cert.pem"
		private_key_path = "key.pem"
	`)

	s.requireAttestSuccessWithPod()

	// write out a different client cert and make sure it is picked up on reload
	clientCert := s.createClientCert()
	s.writeCert(certPath, clientCert)

	s.clock.Add(defaultReloadInterval)
	s.requireAttestFailure("tls: bad certificate")
}

func (s *Suite) TestAttestReachingKubeletViaNodeName() {
	// start up a secure kubelet with "localhost" certificate and token auth
	s.startSecureKubelet(false, "default-token")

	// pick up the node name from the default env value
	s.env["MY_NODE_NAME"] = "localhost"
	s.configureSecure(``)
	s.requireAttestSuccessWithPod()

	// pick up the node name from explicit config (should override env)
	s.env["MY_NODE_NAME"] = "bad-node-name"
	s.configureSecure(`
		node_name = "localhost"
	`)
	s.requireAttestSuccessWithPod()

	// pick up the node name from the overridden env value
	s.env["OVERRIDDEN_NODE_NAME"] = "localhost"
	s.configureSecure(`
		node_name_env = "OVERRIDDEN_NODE_NAME"
	`)
	s.requireAttestSuccessWithPod()
}

func (s *Suite) TestAttestAgainstNodeOverride() {
	s.startInsecureKubelet()
	s.configureInsecure()
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().Empty(resp.Selectors)
}

func (s *Suite) TestConfigure() {
	s.generateCerts("")

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
			name: "non-existent kubelet ca",
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
			name: "non-existent token",
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
			name: "invalid reload interval",
			hcl: `
				kubelet_read_only_port = 10255
				reload_interval = "blah"
			`,
			err: "unable to parse reload interval",
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
		testCase := testCase // alias loop variable as it is used in the closure
		s.T().Run(testCase.name, func(t *testing.T) {
			p, wp := s.newPlugin()
			resp, err := wp.Configure(context.Background(), &spi.ConfigureRequest{
				Configuration: testCase.hcl,
			})
			if testCase.err != "" {
				s.AssertErrorContains(err, testCase.err)
				return
			}
			require.NotNil(t, testCase.config, "test case missing expected config")

			assert.NoError(t, err)
			spiretest.AssertProtoEqual(t, &spi.ConfigureResponse{}, resp)

			c, err := p.getConfig()
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
				t.Logf("CONFIG: %#v", c.Client.Transport.TLSClientConfig)
				if testCase.config.HasNodeName {
					if assert.NotNil(t, c.Client.Transport.TLSClientConfig.RootCAs) {
						assert.Len(t, c.Client.Transport.TLSClientConfig.RootCAs.Subjects(), 1)
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

func (s *Suite) TestGetPluginInfo() {
	resp, err := s.p.GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	s.NoError(err)
	s.AssertProtoEqual(&spi.GetPluginInfoResponse{}, resp)
}

func (s *Suite) newPlugin() (*Plugin, workloadattestor.Plugin) {
	p := New()
	p.fs = testFS(s.dir)
	p.clock = s.clock
	p.getenv = func(key string) string {
		return s.env[key]
	}

	var wp workloadattestor.Plugin
	s.LoadPlugin(builtin(p), &wp)
	return p, wp
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
	s.Require().NoError(ioutil.WriteFile(realPath, []byte(data), 0600))
}

func (s *Suite) serveHTTP(w http.ResponseWriter, req *http.Request) {
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

func (s *Suite) configure(configuration string) {
	_, err := s.p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	s.Require().NoError(err)
}

func (s *Suite) configureInsecure() {
	s.configure(fmt.Sprintf(`
		kubelet_read_only_port = %d
		max_poll_attempts = 5
		poll_retry_interval = "1s"
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

func (s *Suite) startSecureKubelet(hostNetworking bool, token string) {
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
				Certificate: [][]byte{s.kubeletCert.Raw},
				PrivateKey:  kubeletKey,
			},
		},
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}
	server.StartTLS()
	s.setServer(server)
}

func (s *Suite) configureSecure(extraConfig string) {
	configuration := fmt.Sprintf(`
		kubelet_secure_port = %d
	`, s.kubeletPort())
	configuration += extraConfig

	s.configure(configuration)
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

func (s *Suite) requireAttestSuccessWithPod() {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)
	s.requireAttestSuccess(testPodSelectors)
}

func (s *Suite) requireAttestSuccessWithKindPod() {
	s.addPodListResponse(kindPodListFilePath)
	s.addCgroupsResponse(cgPidInKindPodFilePath)
	s.requireAttestSuccess(testKindPodSelectors)
}

func (s *Suite) requireAttestSuccessWithPodSystemdCgroups() {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgSystemdPidInPodFilePath)
	s.requireAttestSuccess(testPodSelectors)
}

func (s *Suite) requireAttestSuccessWithInitPod() {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgInitPidInPodFilePath)
	s.requireAttestSuccess(testInitPodSelectors)
}

func (s *Suite) requireAttestSuccess(expectedSelectors []*common.Selector) {
	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.requireSelectorsEqual(expectedSelectors, resp.Selectors)
}

func (s *Suite) requireAttestFailure(contains string) {
	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, contains)
	s.Require().Nil(resp)
}

func (s *Suite) requireSelectorsEqual(expected, actual []*common.Selector) {
	// assert the selectors (sorting for consistency)
	util.SortSelectors(actual)
	s.RequireProtoListEqual(expected, actual)
}

func (s *Suite) goAttest() <-chan attestResult {
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

func (s *Suite) addPodListResponse(fixturePath string) {
	podList, err := ioutil.ReadFile(fixturePath)
	s.Require().NoError(err)

	s.podList = append(s.podList, podList)
}

func (s *Suite) addCgroupsResponse(fixturePath string) {
	wd, err := os.Getwd()
	s.Require().NoError(err)
	cgroupPath := filepath.Join(s.dir, pidCgroupPath)
	s.Require().NoError(os.MkdirAll(filepath.Dir(cgroupPath), 0755))
	os.Remove(cgroupPath)
	s.Require().NoError(os.Symlink(filepath.Join(wd, fixturePath), cgroupPath))
}

func TestGetContainerIDFromCGroups(t *testing.T) {
	makeCGroups := func(groupPaths []string) []cgroups.Cgroup {
		var out []cgroups.Cgroup
		for _, groupPath := range groupPaths {
			out = append(out, cgroups.Cgroup{
				GroupPath: groupPath,
			})
		}
		return out
	}

	for _, tt := range []struct {
		name        string
		cgroupPaths []string
		containerID string
		err         string
	}{
		{
			name:        "no cgroups",
			cgroupPaths: []string{},
			containerID: "",
			err:         "",
		},
		{
			name: "no container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
			},
			containerID: "",
			err:         "",
		},
		{
			name: "one container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			},
			containerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			err:         "",
		},
		{
			name: "more than one container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
				"/kubepods/kubepods/besteffort/pod6bd2a4d3-a55a-4450-b6fd-2a7ecc72c904/a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
			},
			containerID: "",
			err:         "k8s: multiple container IDs found in cgroups (9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961, a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38)",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			containerID, err := getContainerIDFromCGroups(makeCGroups(tt.cgroupPaths))
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
				assert.Empty(t, containerID)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.containerID, containerID)
		})
	}
}

func TestGetContainerIDFromCGroupPath(t *testing.T) {
	for _, tt := range []struct {
		name        string
		cgroupPath  string
		containerID string
	}{
		{
			name:        "without QOS",
			cgroupPath:  "/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			containerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
		},
		{
			name:        "with QOS",
			cgroupPath:  "/kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/34a2062fd26c805aa8cf814cdfe479322b791f80afb9ea4db02d50375df14b41",
			containerID: "34a2062fd26c805aa8cf814cdfe479322b791f80afb9ea4db02d50375df14b41",
		},
		{
			name:        "docker for desktop with QOS",
			cgroupPath:  "/kubepods/kubepods/besteffort/pod6bd2a4d3-a55a-4450-b6fd-2a7ecc72c904/a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
			containerID: "a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
		},
		{
			name:        "kind with QOS",
			cgroupPath:  "/docker/93529524695bb00d91c1f6dba692ea8d3550c3b94fb2463af7bc9ec82f992d26/kubepods/besteffort/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
			containerID: "09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:        "systemd with QOS and container runtime",
			cgroupPath:  "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48913c-b29f-11e7-9350-020968147796.slice/docker-9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961.scope",
			containerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
		},
		{
			name:       "not kubepods",
			cgroupPath: "/something/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:       "just pod uid and container",
			cgroupPath: "/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:       "just container segment",
			cgroupPath: "/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:       "no container segment",
			cgroupPath: "/kubepods/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80",
		},
		{
			name:       "no pod uid segment",
			cgroupPath: "/kubepods/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:        "cri-containerd",
			cgroupPath:  "/kubepods-besteffort-pod72f7f152_440c_66ac_9084_e0fc1d8a910c.slice:cri-containerd:b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2",
			containerID: "b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("cgroup path=%s", tt.cgroupPath)
			containerID, ok := getContainerIDFromCGroupPath(tt.cgroupPath)
			if tt.containerID == "" {
				assert.False(t, ok)
				assert.Empty(t, containerID)
				return
			}
			assert.True(t, ok)
			assert.Equal(t, tt.containerID, containerID)
		})
	}
}

type testFS string

func (fs testFS) Open(path string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(fs), path))
}
