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

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/test/mock/common/filesystem"
	"github.com/spiffe/spire/test/mock/common/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pid                       = 123
	kubeletReadOnlyPort       = "10255"
	podsURL                   = "http://localhost:" + kubeletReadOnlyPort + "/pods"
	validConfig               = `{"kubelet_read_only_port":"` + kubeletReadOnlyPort + `"}`
	invalidConfig             = `{"kubelet_read_only_port":"invalid"}`
	podListFilePath           = "../../../../../test/fixture/workloadattestor/k8s/pod_list.json"
	podListNotRunningFilePath = "../../../../../test/fixture/workloadattestor/k8s/pod_list_not_running.json"
	cgPidInPodFilePath        = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_in_pod.txt"
	cgInitPidInPodFilePath    = "../../../../../test/fixture/workloadattestor/k8s/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath     = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_not_in_pod.txt"
)

var (
	pidCgroupPath = fmt.Sprintf("/proc/%v/cgroup", pid)

	ctx = context.Background()
)

func InitPlugin(t *testing.T, client httpClient, fs fileSystem) workloadattestor.WorkloadAttestor {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: validConfig,
	}

	p := New()
	p.httpClient = client
	p.fs = fs

	_, err := p.Configure(ctx, pluginConfig)
	assert.NoError(t, err)

	// the default retry config is much too long for tests.
	p.pollRetryInterval = time.Millisecond
	p.maxPollAttempts = 3
	return p
}

func TestK8s_AttestPidInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podList, err := ioutil.ReadFile(podListFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podList)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(pidCgroupPath).Return(os.Open(cgPidInPodFilePath))

	plugin := InitPlugin(t, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(ctx, &req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestK8s_AttestInitPidInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podList, err := ioutil.ReadFile(podListFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podList)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(pidCgroupPath).Return(os.Open(cgInitPidInPodFilePath))

	plugin := InitPlugin(t, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(ctx, &req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestK8s_AttestPidInPodAfterRetry(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podList, err := ioutil.ReadFile(podListFilePath)
	require.NoError(t, err)

	podListNotRunning, err := ioutil.ReadFile(podListNotRunningFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podListNotRunning)),
		}, nil)

	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podListNotRunning)),
		}, nil)

	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podList)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(pidCgroupPath).Return(os.Open(cgPidInPodFilePath))

	plugin := InitPlugin(t, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(ctx, &req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestK8s_AttestPidNotInPodAfterRetry(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podListNotRunning, err := ioutil.ReadFile(podListNotRunningFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podListNotRunning)),
		}, nil)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podListNotRunning)),
		}, nil)
	mockHttpClient.EXPECT().Get(podsURL).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader(podListNotRunning)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(pidCgroupPath).Return(os.Open(cgPidInPodFilePath))

	plugin := InitPlugin(t, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(ctx, &req)
	require.Error(t, err)
	require.Empty(t, resp.Selectors)
}

func TestK8s_AttestPidNotInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(pidCgroupPath).Return(os.Open(cgPidNotInPodFilePath))

	plugin := InitPlugin(t, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(ctx, &req)
	require.NoError(t, err)
	require.Empty(t, resp.Selectors)
}

func TestK8s_ConfigureValidConfig(t *testing.T) {
	assert := assert.New(t)
	p := New()
	r, err := p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: `{"kubelet_read_only_port":1, "max_poll_attempts": 2, "poll_retry_interval": "3s"}`,
	})
	assert.NoError(err)
	assert.Equal(&spi.ConfigureResponse{}, r)
	assert.Equal(p.kubeletReadOnlyPort, 1)
	assert.Equal(p.maxPollAttempts, 2)
	assert.Equal(p.pollRetryInterval, 3*time.Second)
}

func TestK8s_ConfigureInvalidConfig(t *testing.T) {
	assert := assert.New(t)
	p := New()
	r, err := p.Configure(ctx, &spi.ConfigureRequest{
		Configuration: invalidConfig,
	})
	assert.Error(err)
	assert.Equal(&spi.ConfigureResponse{ErrorList: []string{`strconv.ParseInt: parsing "invalid": invalid syntax`}}, r)
}

func TestK8s_GetPluginInfo(t *testing.T) {
	var plugin k8sPlugin
	data, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
