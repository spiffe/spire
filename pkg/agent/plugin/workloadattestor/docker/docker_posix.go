//go:build !windows

package docker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

const (
	defaultPodmanSocketPath         = "unix:///run/podman/podman.sock"
	defaultPodmanSocketPathTemplate = "unix:///run/user/%d/podman/podman.sock"
)

var (
	rePodmanCgroup = regexp.MustCompile(`(?:libpod-|/libpod/)`)
	reUserSliceUID = regexp.MustCompile(`/user-(\d+)\.slice/`)
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

	// PodmanSocketPath is the socket path for rootful Podman (no user namespace).
	// Defaults to "unix:///run/podman/podman.sock".
	PodmanSocketPath string `hcl:"podman_socket_path" json:"podman_socket_path"`

	// PodmanSocketPathTemplate is the socket path template for rootless Podman.
	// The placeholder %d is replaced with the container owner's host UID extracted
	// from the cgroup path. Defaults to "unix:///run/user/%d/podman/podman.sock".
	PodmanSocketPathTemplate string `hcl:"podman_socket_path_template" json:"podman_socket_path_template"`

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

	podmanSocketPath := c.PodmanSocketPath
	if podmanSocketPath == "" {
		podmanSocketPath = defaultPodmanSocketPath
	}
	podmanSocketPathTemplate := c.PodmanSocketPathTemplate
	if podmanSocketPathTemplate == "" {
		podmanSocketPathTemplate = defaultPodmanSocketPathTemplate
	}
	if err := validatePodmanSocketPathTemplate(podmanSocketPathTemplate); err != nil {
		status.ReportErrorf("invalid podman_socket_path_template: %v", err)
		return nil
	}

	return &containerHelper{
		rootDir:                     rootDir,
		containerIDFinder:           containerIDFinder,
		verboseContainerLocatorLogs: c.VerboseContainerLocatorLogs,
		podmanSocketPath:            podmanSocketPath,
		podmanSocketPathTemplate:    podmanSocketPathTemplate,
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
	podmanSocketPath            string
	podmanSocketPathTemplate    string
}

func (h *containerHelper) getContainerIDAndSocket(pID int32, log hclog.Logger) (string, string, error) {
	if h.containerIDFinder != nil {
		cgroupList, err := cgroups.GetCgroups(pID, dirFS(h.rootDir))
		if err != nil {
			return "", "", err
		}
		containerID, err := getContainerIDFromCGroups(h.containerIDFinder, cgroupList)
		if err != nil || containerID == "" {
			return "", "", err
		}
		return containerID, h.detectPodmanSocket(cgroupList, log), nil
	}

	extractor := containerinfo.Extractor{RootDir: h.rootDir, VerboseLogging: h.verboseContainerLocatorLogs}
	containerID, err := extractor.GetContainerID(pID, log)
	if err != nil || containerID == "" {
		return "", "", err
	}

	cgroupList, err := cgroups.GetCgroups(pID, dirFS(h.rootDir))
	if err != nil {
		log.Warn("Failed to read cgroups for Podman detection, falling back to Docker client", "pid", pID, "err", err)
		return containerID, "", nil
	}
	return containerID, h.detectPodmanSocket(cgroupList, log), nil
}

func (h *containerHelper) detectPodmanSocket(cgroupList []cgroups.Cgroup, log hclog.Logger) string {
	for _, cg := range cgroupList {
		if !rePodmanCgroup.MatchString(cg.GroupPath) {
			continue
		}
		if m := reUserSliceUID.FindStringSubmatch(cg.GroupPath); m != nil {
			if uid, err := strconv.ParseUint(m[1], 10, 32); err == nil {
				return fmt.Sprintf(h.podmanSocketPathTemplate, uid)
			}
			log.Warn("Failed to parse rootless Podman UID from cgroup path, falling back to rootful Podman socket", "uid", m[1], "cgroup_path", cg.GroupPath)
		}
		return h.podmanSocketPath
	}
	return ""
}

func validatePodmanSocketPathTemplate(template string) error {
	var placeholders int
	for i := 0; i < len(template); i++ {
		if template[i] != '%' {
			continue
		}
		if i+1 >= len(template) {
			return errors.New("trailing % at end of template")
		}
		switch template[i+1] {
		case '%':
			i++
		case 'd':
			placeholders++
			i++
		default:
			return errors.New("template only supports escaped %% or the %d UID placeholder")
		}
	}

	if placeholders != 1 {
		return errors.New("template must contain exactly one %d UID placeholder")
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
