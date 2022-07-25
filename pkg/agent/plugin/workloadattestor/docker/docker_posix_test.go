//go:build !windows
// +build !windows

package docker

import (
	"io"
	"os"
	"strings"
	"testing"

	dockerclient "github.com/docker/docker/client"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/stretchr/testify/require"
)

const (
	testCgroupEntries = "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973"
)

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

func TestDockerConfigPosix(t *testing.T) {
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
		require.Equal(t, expectFinder, p.c.containerIDFinder)
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
}

func verifyConfigDefault(t *testing.T, c *containerHelper) {
	require.Equal(t, &defaultContainerIDFinder{}, c.containerIDFinder)
}

func withDefaultDataOpt() testPluginOpt {
	fs := newFakeFileSystem(testCgroupEntries)
	return withFileSystem(fs)
}

func withFileSystem(m cgroups.FileSystem) testPluginOpt {
	return func(p *Plugin) {
		p.c.fs = m
	}
}

// this must be the first plugin opt
func withConfig(t *testing.T, cfg string) testPluginOpt {
	return func(p *Plugin) {
		err := doConfigure(t, p, cfg)
		require.NoError(t, err)
	}
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
