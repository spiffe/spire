//go:build !windows

package docker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

type OSConfig struct {
	// DockerSocketPath is the location of the docker daemon socket, this config can be used only on unix environments (default: "unix:///var/run/docker.sock").
	DockerSocketPath string `hcl:"docker_socket_path" json:"docker_socket_path"`

	// ContainerIDCGroupMatchers is a list of patterns used to discover container IDs from cgroup entries.
	// See the documentation for cgroup.NewContainerIDFinder in the cgroup subpackage for more information. (Unix)
	ContainerIDCGroupMatchers []string `hcl:"container_id_cgroup_matchers" json:"container_id_cgroup_matchers"`

	// UseNewContainerLocator, if true, uses the new container locator
	// mechanism instead of cgroup matchers. Currently defaults to false if
	// unset. This will default to true in a future release. (Unix)
	UseNewContainerLocator *bool `hcl:"use_new_container_locator"`

	// VerboseContainerLocatorLogs, if true, dumps extra information to the log
	// about mountinfo and cgroup information used to locate the container.
	VerboseContainerLocatorLogs bool `hcl:"verbose_container_locator_logs"`

	// Used by tests to use a fake /proc directory instead of the real one
	rootDir string
}

func (p *Plugin) createHelper(c *dockerPluginConfig, status *pluginconf.Status) *containerHelper {
	useNewContainerLocator := c.UseNewContainerLocator == nil || *c.UseNewContainerLocator

	var containerIDFinder cgroup.ContainerIDFinder
	if len(c.ContainerIDCGroupMatchers) > 0 {
		if useNewContainerLocator {
			status.ReportError("the new container locator and custom cgroup matchers cannot both be used; please open an issue if the new container locator fails to locate workload containers in your environment; to continue using custom matchers set use_new_container_locator=false")
			return nil
		}
		p.log.Warn("Using the legacy container locator with custom cgroup matchers. This feature will be removed in a future release.")
		status.ReportInfo("Using the legacy container locator with custom cgroup matchers. This feature will be removed in a future release.")
		var err error
		containerIDFinder, err = cgroup.NewContainerIDFinder(c.ContainerIDCGroupMatchers)
		if err != nil {
			status.ReportError(err.Error())
			return nil
		}
	} else {
		status.ReportInfo("Using the new container locator")
	}

	rootDir := c.rootDir
	if rootDir == "" {
		rootDir = "/"
	}

	return &containerHelper{
		rootDir:                     rootDir,
		containerIDFinder:           containerIDFinder,
		verboseContainerLocatorLogs: c.VerboseContainerLocatorLogs,
	}
}

type dirFS string

func (d dirFS) Open(p string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(d), p))
}

type containerHelper struct {
	rootDir                     string
	containerIDFinder           cgroup.ContainerIDFinder
	verboseContainerLocatorLogs bool
}

func (h *containerHelper) getContainerID(pID int32, log hclog.Logger) (string, error) {
	if h.containerIDFinder != nil {
		cgroupList, err := cgroups.GetCgroups(pID, dirFS(h.rootDir))
		if err != nil {
			return "", err
		}
		return getContainerIDFromCGroups(h.containerIDFinder, cgroupList)
	}

	extractor := containerinfo.Extractor{RootDir: h.rootDir, VerboseLogging: h.verboseContainerLocatorLogs}
	return extractor.GetContainerID(pID, log)
}

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerSocketPath
}

// getContainerIDFromCGroups returns the container ID from a set of cgroups
// using the given finder. The container ID found on each cgroup path (if any)
// must be consistent. If no container ID is found among the cgroups, i.e.,
// this isn't a docker workload, the function returns an empty string. If more
// than one container ID is found, or the "found" container ID is blank, the
// function will fail.
func getContainerIDFromCGroups(finder cgroup.ContainerIDFinder, cgroups []cgroups.Cgroup) (string, error) {
	var hasDockerEntries bool
	var containerID string
	for _, cgroup := range cgroups {
		candidate, ok := finder.FindContainerID(cgroup.GroupPath)
		if !ok {
			continue
		}

		hasDockerEntries = true

		switch {
		case containerID == "":
			// This is the first container ID found so far.
			containerID = candidate
		case containerID != candidate:
			// More than one container ID found in the cgroups.
			return "", fmt.Errorf("workloadattestor/docker: multiple container IDs found in cgroups (%s, %s)",
				containerID, candidate)
		}
	}

	switch {
	case !hasDockerEntries:
		// Not a docker workload. Since it is expected that non-docker workloads will call the
		// workload API, it is fine to return a response without any selectors.
		return "", nil
	case containerID == "":
		// The "finder" found a container ID, but it was blank. This is a
		// defensive measure against bad matcher patterns and shouldn't
		// be possible with the default finder.
		return "", errors.New("workloadattestor/docker: a pattern matched, but no container id was found")
	default:
		return containerID, nil
	}
}
