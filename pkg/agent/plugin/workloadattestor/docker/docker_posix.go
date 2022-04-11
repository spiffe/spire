//go:build !windows
// +build !windows

package docker

import (
	"errors"
	"fmt"
	"regexp"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createHelper(c *dockerPluginConfig, log hclog.Logger) (*containerHelper, error) {
	var containerIDFinder cgroup.ContainerIDFinder = &defaultContainerIDFinder{}
	var err error
	if len(c.ContainerIDCGroupMatchers) > 0 {
		containerIDFinder, err = cgroup.NewContainerIDFinder(c.ContainerIDCGroupMatchers)
		if err != nil {
			return nil, err
		}
	}

	return &containerHelper{
		fs:                cgroups.OSFileSystem{},
		containerIDFinder: containerIDFinder,
		log:               log,
	}, nil
}

type containerHelper struct {
	containerIDFinder cgroup.ContainerIDFinder
	fs                cgroups.FileSystem
	log               hclog.Logger
}

func (h *containerHelper) getContainerID(pID int32) (string, error) {
	cgroupList, err := cgroups.GetCgroups(pID, h.fs)
	if err != nil {
		return "", err
	}

	return getContainerIDFromCGroups(h.containerIDFinder, cgroupList)
}

func validateOS(c *dockerPluginConfig) error {
	if c.DockerHost != "" {
		return status.Error(codes.InvalidArgument, "invalid configuration: docker_host is not supported in this platform; please use docker_socket_path instead")
	}

	return nil
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
