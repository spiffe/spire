//go:build !windows

package docker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/gogo/status"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"google.golang.org/grpc/codes"
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

func createHelper(c *dockerPluginConfig, log hclog.Logger) (*containerHelper, error) {
	var containerIDFinder cgroup.ContainerIDFinder

	switch {
	case c.UseNewContainerLocator != nil && *c.UseNewContainerLocator:
		if len(c.ContainerIDCGroupMatchers) > 0 {
			return nil, status.Error(codes.InvalidArgument, "the new container locator and custom cgroup matchers cannot both be used")
		}
		log.Info("Using the new container locator")
	case len(c.ContainerIDCGroupMatchers) > 0:
		log.Warn("Using the legacy container locator with custom cgroup matchers. The new locator will be enabled by default in a future release. Consider using it now by setting `use_new_container_locator=true`.")
		var err error
		containerIDFinder, err = cgroup.NewContainerIDFinder(c.ContainerIDCGroupMatchers)
		if err != nil {
			return nil, err
		}
	default:
		log.Warn("Using the legacy container locator. The new locator will be enabled by default in a future release. Consider using it now by setting `use_new_container_locator=true`.")
		containerIDFinder = &defaultContainerIDFinder{}
	}

	rootDir := c.rootDir
	if rootDir == "" {
		rootDir = "/"
	}

	return &containerHelper{
		rootDir:                     rootDir,
		containerIDFinder:           containerIDFinder,
		verboseContainerLocatorLogs: c.VerboseContainerLocatorLogs,
	}, nil
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
	return extractor.GetContainerID(int(pID), log)
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

type defaultContainerIDFinder struct{}

// FindContainerID returns the container ID in the given cgroup path. The cgroup
// path must have the whole word "docker" at some point in the path followed
// at some point by a 64 hex-character container ID. If the cgroup path does
// not match the above description, the method returns false.
func (f *defaultContainerIDFinder) FindContainerID(cgroupPath string) (string, bool) {
	m := dockerCGroupRE.FindStringSubmatch(cgroupPath)
	if m != nil {
		return m[1], true
	}
	return "", false
}

// dockerCGroupRE matches cgroup paths that have the following properties.
// 1) `\bdocker\b` the whole word docker
// 2) `.+` followed by one or more characters (which will start on a word boundary due to #1)
// 3) `\b([[:xdigit:]][64])\b` followed by a 64 hex-character container id on word boundary
//
// The "docker" prefix and 64-hex character container id can be anywhere in the path. The only
// requirement is that the docker prefix comes before the id.
var dockerCGroupRE = regexp.MustCompile(`\bdocker\b.+\b([[:xdigit:]]{64})\b`)
