//go:build !windows

package slurm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const testPID = 123

var ctx = context.Background()

func TestAttest(t *testing.T) {
	testCases := []struct {
		name           string
		cgroups        string
		selectorValues []string
		expectCode     codes.Code
		expectContains string
	}{
		{
			name:           "sluid job, numeric step",
			cgroups:        "0::/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_0/user/task_0\n",
			selectorValues: []string{"sluid:s5K1KKYAYG5D00", "step:0"},
		},
		{
			name:           "numeric job id, batch step",
			cgroups:        "0::/system.slice/slurmstepd.scope/job_3385/step_batch/slurm\n",
			selectorValues: []string{"job_id:3385", "step:batch"},
		},
		{
			name:           "numeric job id, extern step",
			cgroups:        "0::/system.slice/slurmstepd.scope/job_42/step_extern/user/task_0\n",
			selectorValues: []string{"job_id:42", "step:extern"},
		},
		{
			name:           "sluid job, interactive step",
			cgroups:        "0::/system.slice/slurmstepd.scope/sEKNKTV3WPV500/step_interactive/user/task_0\n",
			selectorValues: []string{"sluid:sEKNKTV3WPV500", "step:interactive"},
		},
		{
			name:           "multiple-slurmd node scope",
			cgroups:        "0::/system.slice/node1_slurmstepd.scope/job_100/step_1/slurm\n",
			selectorValues: []string{"job_id:100", "step:1"},
		},
		{
			name:    "not a slurm workload",
			cgroups: "0::/system.slice/docker-0123456789abcdef.scope\n",
		},
		{
			name:    "plain unix process",
			cgroups: "0::/user.slice/user-1000.slice/session-3.scope\n",
		},
		{
			name:           "conflicting slurm jobs",
			cgroups:        "0::/system.slice/slurmstepd.scope/job_1/step_0/slurm\n0::/system.slice/slurmstepd.scope/job_2/step_0/slurm\n",
			expectCode:     codes.FailedPrecondition,
			expectContains: "multiple Slurm jobs found in cgroups",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			p := loadPlugin(t, log, testCase.cgroups)

			selectors, err := p.Attest(ctx, testPID)

			if testCase.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, testCase.expectCode, testCase.expectContains)
				require.Nil(t, selectors)
				return
			}

			require.NoError(t, err)
			var selectorValues []string
			for _, selector := range selectors {
				require.Equal(t, "slurm", selector.Type)
				selectorValues = append(selectorValues, selector.Value)
			}
			require.Equal(t, testCase.selectorValues, selectorValues)
		})
	}
}

func loadPlugin(t *testing.T, log logrus.FieldLogger, cgroups string) workloadattestor.WorkloadAttestor {
	rootDir := spiretest.TempDir(t)
	procPidPath := filepath.Join(rootDir, "proc", "123")
	require.NoError(t, os.MkdirAll(procPidPath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(procPidPath, "cgroup"), []byte(cgroups), 0600))

	p := New()
	p.rootDir = rootDir

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1, plugintest.Log(log))
	return v1
}
