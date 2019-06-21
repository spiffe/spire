package docker

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	gomock "github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/spire/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	filesystem_mock "github.com/spiffe/spire/test/mock/common/filesystem"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestDockerLabels(t *testing.T) {
	tests := []struct {
		desc                string
		mockContainerLabels map[string]string
		mockImageID         string
		requireResult       func(*testing.T, *workloadattestor.AttestResponse)
	}{
		{
			desc:                "single label",
			mockContainerLabels: map[string]string{"this": "that"},
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 1)
				require.Equal(t, "docker", res.Selectors[0].Type)
				require.Equal(t, "label:this:that", res.Selectors[0].Value)
			},
		},
		{
			desc:                "many labels",
			mockContainerLabels: map[string]string{"this": "that", "here": "there", "up": "down"},
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 3)
				expectedLabels := map[string]bool{
					"label:this:that":  true,
					"label:here:there": true,
					"label:up:down":    true,
				}
				for _, selector := range res.Selectors {
					require.Equal(t, "docker", selector.Type)
					require.Contains(t, expectedLabels, selector.Value)
				}
			},
		},
		{
			desc:                "no labels for container",
			mockContainerLabels: map[string]string{},
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 0)
			},
		},
		{
			desc:        "image id",
			mockImageID: "my-docker-image",
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 1)
				require.Equal(t, "docker", res.Selectors[0].Type)
				require.Equal(t, "image_id:my-docker-image", res.Selectors[0].Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockDocker := NewMockDockerClient(mockCtrl)
			mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)

			p := New()
			p.docker = mockDocker
			p.fs = mockFS
			p.cgroupContainerIndex = 1
			p.cgroupPrefix = "/docker"

			cgroupFile, cleanup := newTestFile(t, "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973")
			defer cleanup()
			ctx := context.Background()
			container := types.ContainerJSON{
				Config: &container.Config{
					Labels: tt.mockContainerLabels,
					Image:  tt.mockImageID,
				},
			}
			mockFS.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgroupFile))
			mockDocker.EXPECT().ContainerInspect(ctx, "6469646e742065787065637420616e796f6e6520746f20726561642074686973").Return(container, nil)

			res, err := p.Attest(ctx, &workloadattestor.AttestRequest{Pid: 123})
			require.NoError(t, err)
			require.NotNil(t, res)
			tt.requireResult(t, res)
		})
	}
}

func newTestFile(t *testing.T, data string) (filename string, cleanup func()) {
	f, err := ioutil.TempFile("", "docker-test")
	require.NoError(t, err)
	_, err = f.Write([]byte(data))
	require.NoError(t, err)
	return f.Name(), func() { os.Remove(f.Name()) }
}

func TestDockerCgroupFormatErrors(t *testing.T) {
	tests := []struct {
		desc                    string
		cfgCgroupPrefix         string
		cfgCgroupContainerIndex int
		mockCgroupEntries       string
		expectErr               string
	}{
		{
			desc:                    "no container id found at requested index",
			cfgCgroupPrefix:         "/docker",
			cfgCgroupContainerIndex: 2,
			mockCgroupEntries:       "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973",
			expectErr:               `workloadattestor/docker: no cgroup "/docker" entries found at index 2`,
		},
		{
			desc:                    "no cgroup prefix found is ok",
			cfgCgroupPrefix:         "/foo",
			cfgCgroupContainerIndex: 2,
			mockCgroupEntries:       "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)

			p := New()
			p.fs = mockFS
			p.cgroupContainerIndex = tt.cfgCgroupContainerIndex
			p.cgroupPrefix = tt.cfgCgroupPrefix

			cgroupFile, cleanup := newTestFile(t, tt.mockCgroupEntries)
			defer cleanup()
			mockFS.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgroupFile))

			res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				require.Nil(t, res)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res.Selectors, 0)
		})
	}
}

func TestCgroupFileNotFound(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)

	p := New()
	p.fs = mockFS

	mockFS.EXPECT().Open("/proc/123/cgroup").Return(nil, errors.New("no proc exists"))

	res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no proc exists")
	require.Nil(t, res)
}

func TestDockerError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDocker := NewMockDockerClient(mockCtrl)
	mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)

	p := New()
	p.docker = mockDocker
	p.fs = mockFS
	p.retryer = disabledRetryer

	cgroupFile, cleanup := newTestFile(t, "1:foo:/bar")
	defer cleanup()
	mockFS.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgroupFile))
	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), "bar").
		Return(types.ContainerJSON{}, errors.New("docker error"))

	res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, res)
}

func TestDockerErrorRetries(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDocker := NewMockDockerClient(mockCtrl)
	mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)
	mockClock := clock.NewMock(t)

	p := New()
	p.docker = mockDocker
	p.fs = mockFS
	p.retryer.clock = mockClock

	cgroupFile, cleanup := newTestFile(t, "1:foo:/bar")
	defer cleanup()
	mockFS.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgroupFile))
	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), "bar").
		Return(types.ContainerJSON{}, errors.New("docker error")).
		Times(4)

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 1")
		mockClock.Add(100 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 2")
		mockClock.Add(200 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 3")
		mockClock.Add(400 * time.Millisecond)
	}()

	res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, res)
}

func TestDockerErrorContextCancel(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDocker := NewMockDockerClient(mockCtrl)
	mockFS := filesystem_mock.NewMockFileSystem(mockCtrl)
	mockClock := clock.NewMock(t)

	p := New()
	p.docker = mockDocker
	p.fs = mockFS
	p.retryer.clock = mockClock

	ctx, cancel := context.WithCancel(context.Background())

	cgroupFile, cleanup := newTestFile(t, "1:foo:/bar")
	defer cleanup()
	mockFS.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgroupFile))
	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), "bar").
		Return(types.ContainerJSON{}, errors.New("docker error"))

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after'")
		// cancel the context after the first call
		cancel()
	}()

	res, err := doAttestWithContext(t, ctx, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
	require.Nil(t, res)
}

func TestDockerConfig(t *testing.T) {
	p := New()
	cfg := &spi.ConfigureRequest{
		Configuration: `
docker_socket_path = "unix:///socket_path"
docker_version = "1.20"
cgroup_prefix = "prefix"
cgroup_container_index = 8
`,
	}
	res, err := doConfigure(t, p, cfg)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, p.docker)
	require.Equal(t, "unix:///socket_path", p.docker.(*dockerclient.Client).DaemonHost())
	require.Equal(t, "1.20", p.docker.(*dockerclient.Client).ClientVersion())
	require.Equal(t, "prefix", p.cgroupPrefix)
	require.Equal(t, 8, p.cgroupContainerIndex)
}

func TestDockerConfigDefault(t *testing.T) {
	p := New()
	cfg := &spi.ConfigureRequest{}
	res, err := doConfigure(t, p, cfg)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, p.docker)
	require.Equal(t, dockerclient.DefaultDockerHost, p.docker.(*dockerclient.Client).DaemonHost())
	require.Equal(t, "1.40", p.docker.(*dockerclient.Client).ClientVersion())
	require.Equal(t, "/docker", p.cgroupPrefix)
	require.Equal(t, 1, p.cgroupContainerIndex)
}

func doAttest(t *testing.T, p *DockerPlugin, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	return doAttestWithContext(t, context.Background(), p, req)
}

func doAttestWithContext(t *testing.T, ctx context.Context, p *DockerPlugin, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	var wp workloadattestor.Plugin
	done := spiretest.LoadPlugin(t, builtin(p), &wp)
	defer done()
	return wp.Attest(ctx, req)
}

func doConfigure(t *testing.T, p *DockerPlugin, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	var wp workloadattestor.Plugin
	done := spiretest.LoadPlugin(t, builtin(p), &wp)
	defer done()
	return wp.Configure(context.Background(), req)
}
