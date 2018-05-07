package k8s

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/test/mock/common/filesystem"
	"github.com/spiffe/spire/test/mock/common/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pid                    = 123
	kubeletReadOnlyPort    = "10255"
	validConfig            = `{"kubelet_read_only_port":"` + kubeletReadOnlyPort + `"}`
	invalidConfig          = `{"kubelet_read_only_port":"invalid"}`
	podListFilePath        = "../../../../../test/fixture/workloadattestor/k8s/pod_list.json"
	cgPidInPodFilePath     = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_in_pod.txt"
	cgInitPidInPodFilePath = "../../../../../test/fixture/workloadattestor/k8s/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath  = "../../../../../test/fixture/workloadattestor/k8s/cgroups_pid_not_in_pod.txt"
)

func PluginGenerator(config string, client httpClient, fs fileSystem) (workloadattestor.WorkloadAttestor, *spi.ConfigureResponse, error) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	p := New()
	p.httpClient = client
	p.fs = fs

	r, err := p.Configure(pluginConfig)
	return p, r, err
}

func TestK8s_AttestPidInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podList, err := ioutil.ReadFile(podListFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get("http://localhost:"+kubeletReadOnlyPort+"/pods").Return(
		&http.Response{
			Body: ioutil.NopCloser(bytes.NewReader(podList)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(fmt.Sprintf("/proc/%v/cgroup", pid)).Return(os.Open(cgPidInPodFilePath))

	plugin, _, err := PluginGenerator(validConfig, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(&req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestK8s_AttestInitPidInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	podList, err := ioutil.ReadFile(podListFilePath)
	require.NoError(t, err)

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockHttpClient.EXPECT().Get("http://localhost:"+kubeletReadOnlyPort+"/pods").Return(
		&http.Response{
			Body: ioutil.NopCloser(bytes.NewReader(podList)),
		}, nil)

	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(fmt.Sprintf("/proc/%v/cgroup", pid)).Return(os.Open(cgInitPidInPodFilePath))

	plugin, _, err := PluginGenerator(validConfig, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(&req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Selectors)
}

func TestK8s_AttestPidNotInPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHttpClient := http_client_mock.NewMockhttpClient(mockCtrl)
	mockFilesystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFilesystem.EXPECT().Open(fmt.Sprintf("/proc/%v/cgroup", pid)).Return(os.Open(cgPidNotInPodFilePath))

	plugin, _, err := PluginGenerator(validConfig, mockHttpClient, mockFilesystem)
	req := workloadattestor.AttestRequest{Pid: int32(pid)}
	resp, err := plugin.Attest(&req)
	require.NoError(t, err)
	require.Empty(t, resp.Selectors)
}

func TestK8s_ConfigureValidConfig(t *testing.T) {
	assert := assert.New(t)
	_, r, err := PluginGenerator(validConfig, &http.Client{}, osFS{})
	assert.Nil(err)
	assert.Equal(&spi.ConfigureResponse{}, r)
}

func TestK8s_ConfigureInvalidConfig(t *testing.T) {
	assert := assert.New(t)
	_, r, err := PluginGenerator(invalidConfig, &http.Client{}, osFS{})
	require.Error(t, err)
	assert.Equal(&spi.ConfigureResponse{ErrorList: []string{`strconv.ParseInt: parsing "invalid": invalid syntax`}}, r)
}

func TestK8s_GetPluginInfo(t *testing.T) {
	var plugin k8sPlugin
	data, e := plugin.GetPluginInfo(&spi.GetPluginInfoRequest{})
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}
