package docker

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	gomock "github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	mock_docker "github.com/spiffe/spire/test/mock/agent/plugin/workloadattestor/docker"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

const (
	testCgroupEntries = "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973"
	testContainerID   = "6469646e742065787065637420616e796f6e6520746f20726561642074686973"
)

func TestDockerSelectors(t *testing.T) {
	tests := []struct {
		desc                string
		mockContainerLabels map[string]string
		mockEnv             []string
		mockImageID         string
		requireResult       func(*testing.T, *workloadattestor.AttestResponse)
	}{
		{
			desc:                "single label; single env",
			mockContainerLabels: map[string]string{"this": "that"},
			mockEnv:             []string{"VAR=val"},
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 2)
				require.Equal(t, "docker", res.Selectors[0].Type)
				require.Equal(t, "label:this:that", res.Selectors[0].Value)
				require.Equal(t, "docker", res.Selectors[1].Type)
				require.Equal(t, "env:VAR=val", res.Selectors[1].Value)
			},
		},
		{
			desc:                "many labels; many env",
			mockContainerLabels: map[string]string{"this": "that", "here": "there", "up": "down"},
			mockEnv:             []string{"VAR=val", "VAR2=val"},
			requireResult: func(t *testing.T, res *workloadattestor.AttestResponse) {
				require.Len(t, res.Selectors, 5)
				expectedSelectors := map[string]struct{}{
					"label:this:that":  {},
					"label:here:there": {},
					"label:up:down":    {},
					"env:VAR=val":      {},
					"env:VAR2=val":     {},
				}
				for _, selector := range res.Selectors {
					require.Equal(t, "docker", selector.Type)
					require.Contains(t, expectedSelectors, selector.Value)
				}
			},
		},
		{
			desc:                "no labels or env for container",
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
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockDocker := mock_docker.NewMockDocker(mockCtrl)

			fs := newFakeFileSystem(testCgroupEntries)

			p := newTestPlugin(t, withMockDocker(mockDocker), withFileSystem(fs))

			ctx := context.Background()
			container := types.ContainerJSON{
				Config: &container.Config{
					Labels: tt.mockContainerLabels,
					Image:  tt.mockImageID,
					Env:    tt.mockEnv,
				},
			}
			mockDocker.EXPECT().ContainerInspect(gomock.Any(), testContainerID).Return(container, nil)

			res, err := p.Attest(ctx, &workloadattestor.AttestRequest{Pid: 123})
			require.NoError(t, err)
			require.NotNil(t, res)
			tt.requireResult(t, res)
		})
	}
}

func TestContainerExtraction(t *testing.T) {
	tests := []struct {
		desc      string
		cfg       string
		cgroups   string
		hasMatch  bool
		expectErr string
	}{
		{
			desc:    "no match",
			cgroups: testCgroupEntries,
			cfg: `container_id_cgroup_matchers = [
  "/docker/*/<id>",
]
`,
		},
		{
			desc:    "one miss one match",
			cgroups: testCgroupEntries,
			cfg: `container_id_cgroup_matchers = [
  "/docker/*/<id>",
  "/docker/<id>"
]`,
			hasMatch: true,
		},
		{
			desc:    "no container id",
			cgroups: "10:cpu:/docker/",
			cfg: `container_id_cgroup_matchers = [
  "/docker/<id>"
]`,
			expectErr: "a pattern matched, but no container id was found",
		},
		{
			desc:     "RHEL docker cgroups",
			cgroups:  "4:devices:/system.slice/docker-6469646e742065787065637420616e796f6e6520746f20726561642074686973.scope",
			hasMatch: true,
		},
		{
			desc:     "docker for desktop",
			cgroups:  "6:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973/system.slice/containerd.service",
			hasMatch: true,
		},
		{
			desc:      "more than one id",
			cgroups:   testCgroupEntries + "\n" + "4:devices:/system.slice/docker-41e4ab61d2860b0e1467de0da0a9c6068012761febec402dc04a5a94f32ea867.scope",
			expectErr: "multiple container IDs found in cgroups",
		},
		{
			desc:    "default finder does not match cgroup missing docker prefix",
			cgroups: "4:devices:/system.slice/41e4ab61d2860b0e1467de0da0a9c6068012761febec402dc04a5a94f32ea867.scope",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockDocker := mock_docker.NewMockDocker(mockCtrl)

			fs := newFakeFileSystem(tt.cgroups)

			p := newTestPlugin(
				t,
				withConfig(t, tt.cfg), // this must be the first option
				withMockDocker(mockDocker),
				withFileSystem(fs),
			)

			if tt.hasMatch {
				container := types.ContainerJSON{
					Config: &container.Config{
						Image: "image-id",
					},
				}
				mockDocker.EXPECT().ContainerInspect(gomock.Any(), testContainerID).Return(container, nil)
			}
			res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				require.Nil(t, res)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, res)

			if tt.hasMatch {
				require.Len(t, res.Selectors, 1)
			} else {
				require.Len(t, res.Selectors, 0)
			}
		})
	}
}

func TestCgroupFileNotFound(t *testing.T) {
	p := newTestPlugin(t, withFileSystem(FakeFileSystem{}))

	res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "file does not exist")
	require.Nil(t, res)
}

func TestDockerError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDocker := mock_docker.NewMockDocker(mockCtrl)

	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withMockDocker(mockDocker),
		withFileSystem(fs),
		withDisabledRetryer(),
	)

	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), testContainerID).
		Return(types.ContainerJSON{}, errors.New("docker error"))

	res, err := doAttest(t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, res)
}

func TestDockerErrorRetries(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDocker := mock_docker.NewMockDocker(mockCtrl)
	mockClock := clock.NewMock(t)

	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withMockDocker(mockDocker),
		withFileSystem(fs),
	)

	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), testContainerID).
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
	mockDocker := mock_docker.NewMockDocker(mockCtrl)
	mockClock := clock.NewMock(t)

	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withMockDocker(mockDocker),
		withFileSystem(fs),
	)

	ctx, cancel := context.WithCancel(context.Background())

	mockDocker.EXPECT().
		ContainerInspect(gomock.Any(), testContainerID).
		Return(types.ContainerJSON{}, errors.New("docker error"))

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after'")
		// cancel the context after the first call
		cancel()
	}()

	res, err := doAttestWithContext(ctx, t, p, &workloadattestor.AttestRequest{Pid: 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
	require.Nil(t, res)
}

func TestDockerConfig(t *testing.T) {
	t.Run("good matchers; custom docker options", func(t *testing.T) {
		expectFinder, err := cgroup.NewContainerIDFinder([]string{"/docker/<id>"})
		require.NoError(t, err)

		p := newTestPlugin(t, withConfig(t, `
docker_socket_path = "unix:///socket_path"
docker_version = "1.20"
container_id_cgroup_matchers = [
  "/docker/<id>",
]
`))
		require.NotNil(t, p.docker)
		require.Equal(t, "unix:///socket_path", p.docker.(*dockerclient.Client).DaemonHost())
		require.Equal(t, "1.20", p.docker.(*dockerclient.Client).ClientVersion())
		require.Equal(t, expectFinder, p.containerIDFinder)
	})
	t.Run("bad matcher", func(t *testing.T) {
		p := New()
		cfg := &spi.ConfigureRequest{
			Configuration: `
container_id_cgroup_matchers = [
	"/docker/",
]`,
		}

		_, err := doConfigure(t, p, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), `must contain the container id token "<id>" exactly once`)
	})
	t.Run("bad hcl", func(t *testing.T) {
		p := New()
		cfg := &spi.ConfigureRequest{
			Configuration: `
container_id_cgroup_matchers = [
	"/docker/"`,
		}

		_, err := doConfigure(t, p, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error parsing list, expected comma or list end")
	})
}

func TestDockerConfigDefault(t *testing.T) {
	p := newTestPlugin(t)

	require.NotNil(t, p.docker)
	require.Equal(t, dockerclient.DefaultDockerHost, p.docker.(*dockerclient.Client).DaemonHost())
	require.Equal(t, "1.41", p.docker.(*dockerclient.Client).ClientVersion())
	require.Equal(t, &defaultContainerIDFinder{}, p.containerIDFinder)
}

func doAttest(t *testing.T, p *Plugin, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	return doAttestWithContext(context.Background(), t, p, req)
}

func doAttestWithContext(ctx context.Context, t *testing.T, p *Plugin, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	var wp workloadattestor.Plugin
	done := spiretest.LoadPlugin(t, builtin(p), &wp)
	defer done()
	return wp.Attest(ctx, req)
}

func doConfigure(t *testing.T, p *Plugin, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	var wp workloadattestor.Plugin
	done := spiretest.LoadPlugin(t, builtin(p), &wp)
	defer done()
	return wp.Configure(context.Background(), req)
}

type testPluginOpt func(*Plugin)

func withMockDocker(m *mock_docker.MockDocker) testPluginOpt {
	return func(p *Plugin) {
		p.docker = m
	}
}

func withFileSystem(m cgroups.FileSystem) testPluginOpt {
	return func(p *Plugin) {
		p.fs = m
	}
}

func withMockClock(c *clock.Mock) testPluginOpt {
	return func(p *Plugin) {
		p.retryer.clock = c
	}
}

func withDisabledRetryer() testPluginOpt {
	return func(p *Plugin) {
		p.retryer = disabledRetryer
	}
}

// this must be the first plugin opt
func withConfig(t *testing.T, cfg string) testPluginOpt {
	return func(p *Plugin) {
		cfgReq := &spi.ConfigureRequest{
			Configuration: cfg,
		}
		resp, err := doConfigure(t, p, cfgReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}
}

func newTestPlugin(t *testing.T, opts ...testPluginOpt) *Plugin {
	p := New()
	resp, err := doConfigure(t, p, &spi.ConfigureRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	for _, o := range opts {
		o(p)
	}
	return p
}

func newFakeFileSystem(cgroups string) FakeFileSystem {
	return FakeFileSystem{
		Files: map[string]string{
			"/proc/123/cgroup": cgroups,
		},
	}
}

type FakeFileSystem struct {
	Files map[string]string
}

func (fs FakeFileSystem) Open(path string) (io.ReadCloser, error) {
	data, ok := fs.Files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return ioutil.NopCloser(strings.NewReader(data)), nil
}
