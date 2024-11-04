//go:build !windows

package containerinfo

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/mount-utils"
)

var (
	// This regex covers both the cgroupfs and systemd rendering of the pod
	// UID. The dashes are replaced with underscores in the systemd rendition.
	rePodUID = regexp.MustCompile(`\b(?:pod([[:xdigit:]]{8}[-_][[:xdigit:]]{4}[-_][[:xdigit:]]{4}[-_][[:xdigit:]]{4}[-_][[:xdigit:]]{12}))\b`)

	// The container ID is a 64-character hex string, by convention.
	reContainerID = regexp.MustCompile(`\b([[:xdigit:]]{64})\b`)

	// underToDash replaces underscores with dashes. The systemd cgroups driver
	// doesn't allow dashes so the pod UID component has dashes replaced with
	// underscores by the Kubelet.
	underToDash = strings.NewReplacer("_", "-")
)

type Extractor struct {
	RootDir        string
	VerboseLogging bool
}

func (e *Extractor) GetContainerID(pid int, log hclog.Logger) (string, error) {
	_, containerID, err := e.extractInfo(pid, log, false)
	return containerID, err
}

func (e *Extractor) GetPodUIDAndContainerID(pid int, log hclog.Logger) (types.UID, string, error) {
	return e.extractInfo(pid, log, true)
}

func (e *Extractor) extractInfo(pid int, log hclog.Logger, extractPodUID bool) (types.UID, string, error) {
	// Try to get the information from /proc/pid/mountinfo first. Otherwise,
	// fall back to /proc/pid/cgroup. If it isn't in mountinfo, then the
	// workload being attested likely originates in the same Pod as the agent.
	//
	// It may not be possible to attest a process running in the same container
	// as the agent because, depending on how cgroups are being used,
	// /proc/<pid>/mountinfo or /proc/<pid>/cgroup may not contain any
	// information on the container ID or pod.

	podUID, containerID, err := e.extractPodUIDAndContainerIDFromMountInfo(pid, log, extractPodUID)
	if err != nil {
		return "", "", err
	}

	if containerID == "" {
		podUID, containerID, err = e.extractPodUIDAndContainerIDFromCGroups(pid, log, extractPodUID)
		if err != nil {
			return "", "", err
		}
	}

	return podUID, containerID, nil
}

func (e *Extractor) extractPodUIDAndContainerIDFromMountInfo(pid int, log hclog.Logger, extractPodUID bool) (types.UID, string, error) {
	mountInfoPath := filepath.Join(e.RootDir, "/proc", fmt.Sprint(pid), "mountinfo")

	mountInfos, err := mount.ParseMountInfo(mountInfoPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", nil
		}
		return "", "", status.Errorf(codes.Internal, "failed to parse mount info at %q: %v", mountInfoPath, err)
	}

	if e.VerboseLogging {
		for i, mountInfo := range mountInfos {
			log.Debug("PID mount enumerated",
				"index", i+1,
				"total", len(mountInfos),
				"type", mountInfo.FsType,
				"root", mountInfo.Root,
			)
		}
	}

	// Scan the cgroup mounts for the pod UID and container ID. The container
	// ID is in the last segment, and the pod UID will be in the second to last
	// segment, but only when we are attesting a different pod than the agent
	// (otherwise, the second to last segment will be "..", since the agent
	// exists in the same pod). In the case of cgroup v1 (or a unified
	// hierarchy), there may exist multiple cgroup mounts. Out of an abundance
	// of caution, all cgroup mounts will be scanned. If a containerID and/or
	// pod UID are picked out of a mount, then those extracted from any of the
	// remaining mounts will be checked to ensure they match. If not, we'll log
	// and fail.
	ex := &extractor{extractPodUID: extractPodUID}
	for _, mountInfo := range mountInfos {
		switch mountInfo.FsType {
		case "cgroup", "cgroup2":
		default:
			continue
		}

		log := log.With("mount_info_root", mountInfo.Root)
		if err := ex.Extract(mountInfo.Root, log); err != nil {
			return "", "", err
		}
	}
	return ex.PodUID(), ex.ContainerID(), nil
}

func (e *Extractor) extractPodUIDAndContainerIDFromCGroups(pid int, log hclog.Logger, extractPodUID bool) (types.UID, string, error) {
	cgroups, err := cgroups.GetCgroups(int32(pid), dirFS(e.RootDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", nil
		}
		return "", "", status.Errorf(codes.Internal, "unable to obtain cgroups: %v", err)
	}

	if e.VerboseLogging {
		for i, cgroup := range cgroups {
			log.Debug("PID cgroup enumerated",
				"index", i+1,
				"total", len(cgroups),
				"path", cgroup.GroupPath,
			)
		}
	}

	ex := &extractor{extractPodUID: extractPodUID}
	for _, cgroup := range cgroups {
		log := log.With("cgroup_path", cgroup.GroupPath)
		if err := ex.Extract(cgroup.GroupPath, log); err != nil {
			return "", "", err
		}
	}
	return ex.PodUID(), ex.ContainerID(), nil
}

type dirFS string

func (d dirFS) Open(p string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(d), p))
}

type extractor struct {
	podUID        types.UID
	containerID   string
	extractPodUID bool
}

func (e *extractor) PodUID() types.UID {
	return e.podUID
}

func (e *extractor) ContainerID() string {
	return e.containerID
}

func (e *extractor) Extract(cgroupPathOrMountRoot string, log hclog.Logger) error {
	podUID, containerID := e.extract(cgroupPathOrMountRoot)

	// An entry with a pod UID overrides an entry without. If we currently have
	// a pod UID and the new entry does not, then ignore it. If we currently
	// don't have a pod UID and the new entry does, then override what we have
	// so far.
	//
	// This helps mitigate situations where there is unified cgroups configured
	// while running kind on macOS, which ends up with something like:
	//     1:cpuset:/docker/93529524695bb00d91c1f6dba692ea8d3550c3b94fb2463af7bc9ec82f992d26/kubepods/besteffort/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6
	//     0::/docker/93529524695bb00d91c1f6dba692ea8d3550c3b94fb2463af7bc9ec82f992d26/system.slice/containerd.service
	// The second entry, with only the container ID of the docker host, should
	// be ignored in favor of the first entry which contains the container ID
	// and pod UID of the container running in Kind.
	switch {
	case e.podUID != "" && podUID == "":
		// We currently have a pod UID and the new entry does not. Ignore it.
		return nil
	case e.podUID == "" && podUID != "":
		// We currently don't have a pod UID but have found one. Override
		// the current values with the new entry.
		e.podUID = podUID
		e.containerID = containerID
	}

	// Check for conflicting answers for the pod UID or container ID. The safe
	// action is to not choose anything.

	if podUID != "" && e.podUID != "" && podUID != e.podUID {
		log.Debug("Workload pod UID conflict",
			"previous", e.podUID,
			"current", podUID,
		)
		return status.Errorf(codes.FailedPrecondition, "multiple pod UIDs found (%q, %q)", e.podUID, podUID)
	}

	if e.containerID != "" && containerID != e.containerID {
		log.Debug("Workload container ID conflict",
			"previous", e.containerID,
			"current", containerID,
		)
		return status.Errorf(codes.FailedPrecondition, "multiple container IDs found (%q, %q)", e.containerID, containerID)
	}

	e.containerID = containerID
	e.podUID = podUID
	return nil
}

func (e *extractor) extract(cgroupPathOrMountRoot string) (types.UID, string) {
	// The container ID is typically in the last segment but in some cases
	// there can other path segments that come after. Further, some
	// combinations of kubernetes/cgroups driver/cgroups version/container
	// runtime, etc., use colon separators between the pod UID and containerID,
	// which means they can end up in the same segment together.
	//
	// The basic algorithm is to walk backwards through the path segments until
	// something that looks like a container ID is located. Once located, and
	// if the extractor is configured for it, we'll continue walking backwards
	// (starting with what's left in the segment the container ID was located
	// in) looking for the pod UID.
	stripSegment := func(p string) (rest string, segment string) {
		rest, segment = path.Split(p)
		rest = strings.TrimSuffix(rest, "/")
		return rest, segment
	}

	rest, segment := stripSegment(cgroupPathOrMountRoot)

	// Walk backwards through the segments looking for the container ID. If
	// found, extract the container ID and truncate the segment so that the
	// remainder can (optionally) be searched for the pod UID below.
	var containerID string
	for segment != "" {
		if indices := reContainerID.FindStringSubmatchIndex(segment); len(indices) > 0 {
			containerID = segment[indices[2]:indices[3]]
			segment = segment[:indices[2]]
			break
		}
		rest, segment = stripSegment(rest)
	}

	// If there is no container ID, then don't try to extract the pod UID.
	if containerID == "" {
		return "", ""
	}

	// If the extractor isn't interested in the pod UID, then we're done.
	if !e.extractPodUID {
		return "", containerID
	}

	// If the container ID occupied the beginning of the last segment, then
	// that segment is consumed, and we should grab the next one.
	if segment == "" {
		rest, segment = stripSegment(rest)
	}

	// Walk backwards through the remaining segments looking for the pod UID.
	var podUID string
	for segment != "" {
		if m := rePodUID.FindStringSubmatch(segment); len(m) > 0 {
			// For systemd, dashes in pod UIDs are escaped to underscores. Reverse that.
			podUID = underToDash.Replace(m[1])
			break
		}
		rest, segment = stripSegment(rest)
	}

	return types.UID(podUID), containerID
}
