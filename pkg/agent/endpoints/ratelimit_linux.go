//go:build linux

package endpoints

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// containerInfoPodUIDResolver resolves the pod UID for a given PID by reading
// the process's cgroup information from procfs.
type containerInfoPodUIDResolver struct {
	extractor containerinfo.Extractor
	hclogger  *log.HCLogAdapter
}

func (r *containerInfoPodUIDResolver) GetPodUID(pid int32) string {
	podUID, _, err := r.extractor.GetPodUIDAndContainerID(pid, r.hclogger)
	if err != nil {
		r.hclogger.Debug("Failed to resolve pod UID; falling back to OS UID", telemetry.PID, pid)
		return ""
	}
	return string(podUID)
}

func newPodUIDResolver(logger logrus.FieldLogger) podUIDResolver {
	return &containerInfoPodUIDResolver{
		extractor: containerinfo.Extractor{RootDir: "/"},
		hclogger:  log.NewHCLogAdapter(logger, "pod_uid_resolver"),
	}
}
