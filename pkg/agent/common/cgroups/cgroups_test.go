package cgroups

import (
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	filesystem_mock "github.com/spiffe/spire/test/mock/common/filesystem"
	"github.com/stretchr/testify/require"
)

const (
	cgSimple    = "../../../../test/fixture/workloadattestor/agentutil/cgroups_simple.txt"
	cgBadFormat = "../../../../test/fixture/workloadattestor/agentutil/cgroups_bad_format.txt"
)

var (
	expectSimpleCgroup = []Cgroup{
		{"11", "hugetlb", "/"},
		{"10", "devices", "/user.slice"},
		{"9", "pids", "/user.slice/user-1000.slice"},
		{"8", "perf_event", "/"},
		{"7", "net_cls,net_prio", "/"},
		{"6", "cpuset", "/"},
		{"5", "memory", "/user.slice"},
		{"4", "cpu,cpuacct", "/user.slice"},
		{"3", "freezer", "/"},
		{"2", "blkio", "/user.slice"},
		{"1", "name=systemd", "/user.slice/user-1000.slice/session-2.scope"},
	}
)

func TestCgroups(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockFileSystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFileSystem.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgSimple))

	cgroups, err := GetCgroups(123, mockFileSystem)
	require.NoError(t, err)
	require.Len(t, cgroups, 11)
	require.Equal(t, expectSimpleCgroup, cgroups)
}

func TestCgroupsBadFormat(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockFileSystem := filesystem_mock.NewMockfileSystem(mockCtrl)
	mockFileSystem.EXPECT().Open("/proc/123/cgroup").Return(os.Open(cgBadFormat))

	cgroups, err := GetCgroups(123, mockFileSystem)
	require.Error(t, err)
	require.Contains(t, err.Error(), `cgroup entry contains 2 colons, but expected at least 2 colons: "11:hugetlb"`)
	require.Nil(t, cgroups)
}
