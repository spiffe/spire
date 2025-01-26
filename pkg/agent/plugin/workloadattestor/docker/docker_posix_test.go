//go:build !windows

package docker

import (
	"os"
	"path/filepath"
	"testing"

	dockerclient "github.com/docker/docker/client"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

const (
	testCgroupEntries = "10:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973"
)

func TestContainerExtraction(t *testing.T) {
	tests := []struct {
		desc        string
		trustDomain string
		cfg         string
		cgroups     string
		hasMatch    bool
		expectErr   string
	}{
		{
			desc:        "no match",
			trustDomain: "example.org",
			cgroups:     testCgroupEntries,
			cfg: `
				use_new_container_locator = false
				container_id_cgroup_matchers = [
					"/docker/*/<id>",
				]
			`,
		},
		{
			desc:        "one miss one match",
			trustDomain: "example.org",
			cgroups:     testCgroupEntries,
			cfg: `
				use_new_container_locator = false
				container_id_cgroup_matchers = [
					"/docker/*/<id>",
					"/docker/<id>"
				]
			`,
			hasMatch: true,
		},
		{
			desc:        "no container id",
			trustDomain: "example.org",
			cgroups:     "10:cpu:/docker/",
			cfg: `
				use_new_container_locator = false
				container_id_cgroup_matchers = [
					"/docker/<id>"
				]
			`,
			expectErr: "a pattern matched, but no container id was found",
		},
		{
			desc:        "RHEL docker cgroups",
			trustDomain: "example.org",
			cgroups:     "4:devices:/system.slice/docker-6469646e742065787065637420616e796f6e6520746f20726561642074686973.scope",
			hasMatch:    true,
		},
		{
			desc:        "docker for desktop",
			trustDomain: "example.org",
			cgroups:     "6:devices:/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973/docker/6469646e742065787065637420616e796f6e6520746f20726561642074686973/system.slice/containerd.service",
			hasMatch:    true,
		},
		{
			desc:        "more than one id",
			trustDomain: "example.org",
			cgroups:     testCgroupEntries + "\n" + "4:devices:/system.slice/docker-41e4ab61d2860b0e1467de0da0a9c6068012761febec402dc04a5a94f32ea867.scope",
			expectErr:   "multiple container IDs found",
		},
		{
			desc:        "default configuration matches cgroup missing docker prefix",
			trustDomain: "example.org",
			cgroups:     "4:devices:/system.slice/6469646e742065787065637420616e796f6e6520746f20726561642074686973.scope",
			hasMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			withRootDirOpt := prepareRootDirOpt(t, tt.cgroups)
			var d Docker = dockerError{}
			if tt.hasMatch {
				d = fakeContainer{
					Image: "image-id",
				}
			}

			p := newTestPlugin(
				t,
				withConfig(t, tt.trustDomain, tt.cfg), // this must be the first option
				withDocker(d),
				withRootDirOpt,
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
	p := newTestPlugin(t, withRootDir(spiretest.TempDir(t)))

	// The new container info extraction code does not consider a missing file
	// to be an error. It just won't return any container ID so attestation
	// won't produce any selectors.
	selectorValues, err := doAttest(t, p)
	require.NoError(t, err)
	require.Empty(t, selectorValues)
}

func TestDockerConfigPosix(t *testing.T) {
	t.Run("good matchers; custom docker options", func(t *testing.T) {
		expectFinder, err := cgroup.NewContainerIDFinder([]string{"/docker/<id>"})
		require.NoError(t, err)

		p := newTestPlugin(t, withConfig(t, "example.org", `
use_new_container_locator = false
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
use_new_container_locator = false
container_id_cgroup_matchers = [
"/docker/",
]`
		err := doConfigure(t, p, "example.org", cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), `must contain the container id token "<id>" exactly once`)
	})
}

func verifyConfigDefault(t *testing.T, c *containerHelper) {
	// The unit tests configure the plugin to use the new container info
	// extraction code so the legacy finder should be set to nil.
	require.Nil(t, c.containerIDFinder)
}

func withDefaultDataOpt(tb testing.TB) testPluginOpt {
	return prepareRootDirOpt(tb, testCgroupEntries)
}

func prepareRootDirOpt(tb testing.TB, cgroups string) testPluginOpt {
	rootDir := spiretest.TempDir(tb)
	procPidPath := filepath.Join(rootDir, "proc", "123")
	require.NoError(tb, os.MkdirAll(procPidPath, 0755))
	cgroupsPath := filepath.Join(procPidPath, "cgroup")
	require.NoError(tb, os.WriteFile(cgroupsPath, []byte(cgroups), 0600))
	return withRootDir(rootDir)
}

func withRootDir(dir string) testPluginOpt {
	return func(p *Plugin) {
		p.c.rootDir = dir
	}
}

// this must be the first plugin opt
func withConfig(t *testing.T, trustDomain string, cfg string) testPluginOpt {
	return func(p *Plugin) {
		err := doConfigure(t, p, trustDomain, cfg)
		require.NoError(t, err)
	}
}
