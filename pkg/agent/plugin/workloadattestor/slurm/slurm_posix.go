//go:build !windows

package slurm

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// slurmCgroupRe matches the Slurm cgroup/v2 hierarchy created by slurmstepd:
//
//	/system.slice/[<nodename>_]slurmstepd.scope/<JOBDIR>/step_<STEP>/{slurm|user}/task_<n>
//
// <JOBDIR> is either "job_<numeric>" (when CgroupJobIdPaths=yes) or a bare SLUID,
// which is Crockford Base32 with a leading 's'. <STEP> is a numeric step id or one
// of the special names (batch, extern, interactive, TBD). Anchoring on
// "slurmstepd.scope/" also matches the "<nodename>_slurmstepd.scope" form used with
// --enable-multiple-slurmd, since that segment ends in "slurmstepd.scope".
var slurmCgroupRe = regexp.MustCompile(`slurmstepd\.scope/(job_\d+|s[0-9A-Za-z]+)/step_([^/]+)`)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
	)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer

	log hclog.Logger

	// rootDir is the filesystem root under which /proc is read. It defaults to
	// "/" and is overridden by tests to point at a fake /proc tree.
	rootDir string
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	rootDir := p.rootDir
	if rootDir == "" {
		rootDir = "/"
	}

	cgroupList, err := cgroups.GetCgroups(req.Pid, os.DirFS(rootDir))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to obtain cgroups: %v", err)
	}

	jobDir, step, err := findSlurmJob(cgroupList)
	if err != nil {
		return nil, err
	}
	if jobDir == "" {
		// Not a Slurm workload. Non-Slurm workloads are expected to call the
		// workload API, so return a response with no selectors and no error.
		return &workloadattestorv1.AttestResponse{}, nil
	}

	var selectorValues []string
	if numeric, ok := strings.CutPrefix(jobDir, "job_"); ok {
		selectorValues = append(selectorValues, makeSelectorValue("job_id", numeric))
	} else {
		selectorValues = append(selectorValues, makeSelectorValue("sluid", jobDir))
	}
	selectorValues = append(selectorValues, makeSelectorValue("step", step))

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

// AttestReference returns Unimplemented. This plugin does not handle
// reference-based workload attestation; the host falls back to PID-based
// Attest when the reference is a WorkloadPIDReference.
func (p *Plugin) AttestReference(_ context.Context, _ *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AttestReference not implemented")
}

// findSlurmJob scans the cgroup paths for the Slurm v2 job/step structure. It
// returns the job directory (a "job_<numeric>" or SLUID token) and the step id.
// If none of the cgroups match, it returns empty strings and no error (not a
// Slurm workload). If the cgroups match more than one distinct job/step, it
// returns an error, since that should never happen for a real workload.
func findSlurmJob(cgroupList []cgroups.Cgroup) (jobDir, step string, err error) {
	for _, cg := range cgroupList {
		m := slurmCgroupRe.FindStringSubmatch(cg.GroupPath)
		if m == nil {
			continue
		}
		switch {
		case jobDir == "":
			jobDir, step = m[1], m[2]
		case jobDir != m[1] || step != m[2]:
			return "", "", status.Errorf(codes.FailedPrecondition,
				"multiple Slurm jobs found in cgroups (%s/step_%s, %s/step_%s)",
				jobDir, step, m[1], m[2])
		}
	}
	return jobDir, step, nil
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}
