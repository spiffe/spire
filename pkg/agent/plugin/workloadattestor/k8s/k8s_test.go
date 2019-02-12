package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	mock "github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	filesystem_mock "github.com/spiffe/spire/test/mock/common/filesystem"
	http_client_mock "github.com/spiffe/spire/test/mock/common/http"
	"github.com/stretchr/testify/suite"
)

const (
	pid                       = 123
	kubeletReadOnlyPort       = 10255
	invalidConfig             = `{"kubelet_read_only_port":"invalid"}`
	podListFilePath           = "../../../../../test/fixture/workloadattestor/k8s/pod_list.json"
	podListNotRunningFilePath = "../../../../../test/fixture/workloadattestor/k8s/pod_list_not_running.json"
	cgPidInPodFilePath        = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_in_pod.txt"
	cgInitPidInPodFilePath    = "../../../../../test/fixture/workloadattestor/k8s/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath     = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_not_in_pod.txt"
)

var (
	pidCgroupPath = fmt.Sprintf("/proc/%v/cgroup", pid)
)

func TestK8sAttestor(t *testing.T) {
	suite.Run(t, new(K8sAttestorSuite))

}

type K8sAttestorSuite struct {
	suite.Suite

	ctrl       *mock.Controller
	p          workloadattestor.Plugin
	fs         *filesystem_mock.MockfileSystem
	httpClient *http_client_mock.MockhttpClient
}

func (s *K8sAttestorSuite) SetupTest() {
	s.ctrl = mock.NewController(s.T())
	s.fs = filesystem_mock.NewMockfileSystem(s.ctrl)
	s.httpClient = http_client_mock.NewMockhttpClient(s.ctrl)

	p := New()
	p.fs = s.fs
	p.httpClient = s.httpClient

	s.p = workloadattestor.NewBuiltIn(p)
	s.configure(time.Millisecond)
}

func (s *K8sAttestorSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *K8sAttestorSuite) configure(pollRetryInterval time.Duration) {
	configuration := fmt.Sprintf(`
	{
		"kubelet_read_only_port": %d,
		"max_poll_attempts": %d,
		"poll_retry_interval": %q
	}
`, kubeletReadOnlyPort, 3, pollRetryInterval)

	_, err := s.p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	s.Require().NoError(err)
}

func (s *K8sAttestorSuite) addPodListResponse(fixturePath string) {
	podList, err := ioutil.ReadFile(fixturePath)
	s.Require().NoError(err)

	podsURL := fmt.Sprintf("http://localhost:%d/pods", kubeletReadOnlyPort)
	s.httpClient.EXPECT().Get(podsURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewReader(podList)),
	}, nil)
}

func (s *K8sAttestorSuite) addCgroupsResponse(fixturePath string) {
	s.fs.EXPECT().Open(pidCgroupPath).Return(os.Open(fixturePath))
}

func (s *K8sAttestorSuite) TestAttestWithPidInPod() {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithInitPidInPod() {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgInitPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithPidInPodAfterRetry() {
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)

	// assert the selectors (sorting for consistency)
	util.SortSelectors(resp.Selectors)
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
	}, resp.Selectors)
}

func (s *K8sAttestorSuite) TestAttestWithPidNotInPodCancelsEarly() {
	// Configure the poll interval really far out to make sure cancellation is
	// the cause for return.
	s.configure(time.Hour)
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
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addPodListResponse(podListNotRunningFilePath)
	s.addCgroupsResponse(cgPidInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "k8s: no selectors found")
	s.Require().Nil(resp)
}

func (s *K8sAttestorSuite) TestAttestWithPidNotInPod() {
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	resp, err := s.p.Attest(context.Background(), &workloadattestor.AttestRequest{
		Pid: int32(pid),
	})
	s.Require().NoError(err)
	s.Require().Empty(resp.Selectors)
}

func (s *K8sAttestorSuite) TestConfigureValidConfig() {
	p := New()
	resp, err := p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `{"kubelet_read_only_port":1, "max_poll_attempts": 2, "poll_retry_interval": "3s"}`,
	})
	s.NoError(err)
	s.Equal(&spi.ConfigureResponse{}, resp)
	s.Equal(p.kubeletReadOnlyPort, 1)
	s.Equal(p.maxPollAttempts, 2)
	s.Equal(p.pollRetryInterval, 3*time.Second)
}

func (s *K8sAttestorSuite) TestConfigureInvalidConfig() {
	p := New()
	resp, err := p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: invalidConfig,
	})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), `k8s: strconv.ParseInt: parsing "invalid": invalid syntax`)
	s.Require().Nil(resp)
}

func (s *K8sAttestorSuite) TestGetPluginInfo() {
	resp, err := s.p.GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	s.NoError(err)
	s.Equal(&spi.GetPluginInfoResponse{}, resp)
}
