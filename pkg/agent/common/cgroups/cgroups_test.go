package cgroups

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// cgSimple is a good set of cgroup entries
	cgSimple = `11:hugetlb:/
10:devices:/user.slice
9:pids:/user.slice/user-1000.slice
8:perf_event:/
7:net_cls,net_prio:/
6:cpuset:/
5:memory:/user.slice
4:cpu,cpuacct:/user.slice
3:freezer:/
2:blkio:/user.slice
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
`
	// cgBadFormat is a malformed set of cgroup entries (missing cgroup-path)
	cgBadFormat = `11:hugetlb
`
	// cgUnified is a good set of cgroup entries including unified
	cgUnified = `10:devices:/user.slice
9:net_cls,net_prio:/
8:blkio:/
7:freezer:/
6:perf_event:/
5:cpuset:/
4:memory:/user.slice
3:pids:/user.slice/user-1000.slice/user@1000.service
2:cpu,cpuacct:/
1:name=systemd:/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service
0::/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service`
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

	expectUnifiedCgroup = []Cgroup{
		{"10", "devices", "/user.slice"},
		{"9", "net_cls,net_prio", "/"},
		{"8", "blkio", "/"},
		{"7", "freezer", "/"},
		{"6", "perf_event", "/"},
		{"5", "cpuset", "/"},
		{"4", "memory", "/user.slice"},
		{"3", "pids", "/user.slice/user-1000.slice/user@1000.service"},
		{"2", "cpu,cpuacct", "/"},
		{"1", "name=systemd", "/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service"},
		{"0", "", "/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service"},
	}
)

func TestCgroups(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{
		Files: map[string]string{
			"/proc/123/cgroup": cgSimple,
		},
	})
	require.NoError(t, err)
	require.Len(t, cgroups, 11)
	require.Equal(t, expectSimpleCgroup, cgroups)
}

func TestCgroupsNotFound(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{})
	require.True(t, os.IsNotExist(err))
	require.Nil(t, cgroups)
}

func TestCgroupsBadFormat(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{
		Files: map[string]string{
			"/proc/123/cgroup": cgBadFormat,
		},
	})
	require.EqualError(t, err, `invalid cgroup entry, contains 2 colon separated fields but expected at least 3: "11:hugetlb"`)
	require.Nil(t, cgroups)
}

func TestUnifiedCgroups(t *testing.T) {
	cgroups, err := GetCgroups(1234, FakeFileSystem{
		Files: map[string]string{
			"/proc/1234/cgroup": cgUnified,
		},
	})
	require.NoError(t, err)
	require.Len(t, cgroups, 11)
	require.Equal(t, expectUnifiedCgroup, cgroups)
}

type FakeFileSystem struct {
	Files map[string]string
}

func (fs FakeFileSystem) Open(path string) (io.ReadCloser, error) {
	data, ok := fs.Files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(strings.NewReader(data)), nil
}
