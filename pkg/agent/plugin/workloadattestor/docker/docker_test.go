package docker

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

const (
	testCgroupEntries = "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973"
	testContainerID   = "6469646e742065787065637420616e796f6e6520746f20726561642074686973"
)

func TestDockerSelectors(t *testing.T) {
	tests := []struct {
		desc                 string
		mockContainerLabels  map[string]string
		mockEnv              []string
		mockImageID          string
		expectSelectorValues []string
	}{
		{
			desc:                "single label; single env",
			mockContainerLabels: map[string]string{"this": "that"},
			mockEnv:             []string{"VAR=val"},
			expectSelectorValues: []string{
				"env:VAR=val",
				"label:this:that",
			},
		},
		{
			desc:                "many labels; many env",
			mockContainerLabels: map[string]string{"this": "that", "here": "there", "up": "down"},
			mockEnv:             []string{"VAR=val", "VAR2=val"},
			expectSelectorValues: []string{
				"env:VAR2=val",
				"env:VAR=val",
				"label:here:there",
				"label:this:that",
				"label:up:down",
			},
		},
		{
			desc:                 "no labels or env for container",
			mockContainerLabels:  map[string]string{},
			expectSelectorValues: nil,
		},
		{
			desc:        "image id",
			mockImageID: "my-docker-image",
			expectSelectorValues: []string{
				"image_id:my-docker-image",
			},
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			d := fakeContainer{
				Labels: tt.mockContainerLabels,
				Image:  tt.mockImageID,
				Env:    tt.mockEnv,
			}

			fs := newFakeFileSystem(testCgroupEntries)

			p := newTestPlugin(t, withDocker(d), withFileSystem(fs))

			selectorValues, err := doAttest(t, p)
			require.NoError(t, err)

			require.Equal(t, tt.expectSelectorValues, selectorValues)
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
			fs := newFakeFileSystem(tt.cgroups)

			var d Docker = dockerError{}
			if tt.hasMatch {
				d = fakeContainer{
					Image: "image-id",
				}
			}

			p := newTestPlugin(
				t,
				withConfig(t, tt.cfg), // this must be the first option
				withDocker(d),
				withFileSystem(fs),
			)

			selectorValues, err := doAttest(t, p)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				require.Nil(t, selectorValues)
				return
			}

			require.NoError(t, err)
			if tt.hasMatch {
				require.Len(t, selectorValues, 1)
			} else {
				require.Len(t, selectorValues, 0)
			}
		})
	}
}

func TestCgroupFileNotFound(t *testing.T) {
	p := newTestPlugin(t, withFileSystem(FakeFileSystem{}))

	selectorValues, err := doAttest(t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file does not exist")
	require.Nil(t, selectorValues)
}

func TestDockerError(t *testing.T) {
	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withFileSystem(fs),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, selectorValues)
}

func TestDockerErrorRetries(t *testing.T) {
	mockClock := clock.NewMock(t)

	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withDocker(dockerError{}),
		withFileSystem(fs),
	)

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 1")
		mockClock.Add(100 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 2")
		mockClock.Add(200 * time.Millisecond)
		mockClock.WaitForAfter(time.Second, "never got call to 'after' 3")
		mockClock.Add(400 * time.Millisecond)
	}()

	selectorValues, err := doAttest(t, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "docker error")
	require.Nil(t, selectorValues)
}

func TestDockerErrorContextCancel(t *testing.T) {
	mockClock := clock.NewMock(t)

	fs := newFakeFileSystem(testCgroupEntries)

	p := newTestPlugin(
		t,
		withMockClock(mockClock),
		withFileSystem(fs),
	)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		mockClock.WaitForAfter(time.Second, "never got call to 'after'")
		// cancel the context after the first call
		cancel()
	}()

	res, err := doAttestWithContext(ctx, t, p)
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
		cfg := `
container_id_cgroup_matchers = [
	"/docker/",
]`
		err := doConfigure(t, p, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), `must contain the container id token "<id>" exactly once`)
	})
	t.Run("bad hcl", func(t *testing.T) {
		p := New()
		cfg := `
container_id_cgroup_matchers = [
	"/docker/"`

		err := doConfigure(t, p, cfg)
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

func doAttest(t *testing.T, p *Plugin) ([]string, error) {
	return doAttestWithContext(context.Background(), t, p)
}

func doAttestWithContext(ctx context.Context, t *testing.T, p *Plugin) ([]string, error) {
	wp := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), wp)
	selectors, err := wp.Attest(ctx, 123)
	if err != nil {
		return nil, err
	}
	var selectorValues []string
	for _, selector := range selectors {
		require.Equal(t, pluginName, selector.Type)
		selectorValues = append(selectorValues, selector.Value)
	}
	sort.Strings(selectorValues)
	return selectorValues, nil
}

func doConfigure(t *testing.T, p *Plugin, cfg string) error {
	var err error
	plugintest.Load(t, builtin(p), new(workloadattestor.V1),
		plugintest.Configure(cfg),
		plugintest.CaptureConfigureError(&err))
	return err
}

type testPluginOpt func(*Plugin)

func withDocker(docker Docker) testPluginOpt {
	return func(p *Plugin) {
		p.docker = docker
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
		err := doConfigure(t, p, cfg)
		require.NoError(t, err)
	}
}

func newTestPlugin(t *testing.T, opts ...testPluginOpt) *Plugin {
	p := New()
	err := doConfigure(t, p, "")
	require.NoError(t, err)

	for _, o := range opts {
		o(p)
	}
	return p
}

type dockerError struct{}

func (dockerError) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	return types.ContainerJSON{}, errors.New("docker error")
}

type fakeContainer container.Config

func (f fakeContainer) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	if containerID != testContainerID {
		return types.ContainerJSON{}, errors.New("expected test container ID")
	}
	config := container.Config(f)
	return types.ContainerJSON{
		Config: &config,
	}, nil
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
	return io.NopCloser(strings.NewReader(data)), nil
}
