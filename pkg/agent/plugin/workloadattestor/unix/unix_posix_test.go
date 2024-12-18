//go:build !windows

package unix

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var ctx = context.Background()

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	dir     string
	log     logrus.FieldLogger
	logHook *test.Hook
}

func (s *Suite) SetupTest() {
	log, logHook := test.NewNullLogger()
	s.log = log
	s.logHook = logHook

	s.dir = s.TempDir()
}

func (s *Suite) TestAttest() {
	unreadableExePath := "/proc/10/unreadable-exe"
	if runtime.GOOS != "linux" {
		unreadableExePath = filepath.Join(s.dir, "unreadable-exe")
	}
	testCases := []struct {
		name           string
		trustDomain    string
		pid            int
		selectorValues []string
		config         string
		expectCode     codes.Code
		expectMsg      string
	}{
		{
			name:        "pid with no uids",
			trustDomain: "example.org",
			pid:         1,
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): UIDs lookup: no UIDs for process",
		},
		{
			name:        "fail to get uids",
			trustDomain: "example.org",
			pid:         2,
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): UIDs lookup: unable to get UIDs for PID 2",
		},
		{
			name:        "user lookup fails",
			trustDomain: "example.org",
			pid:         3,
			selectorValues: []string{
				"uid:1999",
				"gid:2000",
				"group:g2000",
			},
			expectCode: codes.OK,
		},
		{
			name:        "pid with no gids",
			trustDomain: "example.org",
			pid:         4,
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): GIDs lookup: no GIDs for process",
		},
		{
			name:        "fail to get gids",
			trustDomain: "example.org",
			pid:         5,
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): GIDs lookup: unable to get GIDs for PID 5",
		},
		{
			name:        "group lookup fails",
			trustDomain: "example.org",
			pid:         6,
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2999",
			},
			expectCode: codes.OK,
		},
		{
			name:        "primary user and gid",
			trustDomain: "example.org",
			pid:         7,
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2000",
				"group:g2000",
			},
			expectCode: codes.OK,
		},
		{
			name:        "effective user and gid",
			trustDomain: "example.org",
			pid:         8,
			selectorValues: []string{
				"uid:1100",
				"user:u1100",
				"gid:2100",
				"group:g2100",
			},
			expectCode: codes.OK,
		},
		{
			name:        "fail to get process binary path",
			trustDomain: "example.org",
			pid:         9,
			config:      "discover_workload_path = true",
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): path lookup: unable to get EXE for PID 9",
		},
		{
			name:        "fail to hash process binary",
			trustDomain: "example.org",
			pid:         10,
			config:      "discover_workload_path = true",
			expectCode:  codes.Internal,
			expectMsg:   fmt.Sprintf("workloadattestor(unix): SHA256 digest: open %s: no such file or directory", unreadableExePath),
		},
		{
			name:        "process binary exceeds size limits",
			trustDomain: "example.org",
			pid:         11,
			config:      "discover_workload_path = true\nworkload_size_limit = 2",
			expectCode:  codes.Internal,
			expectMsg:   fmt.Sprintf("workloadattestor(unix): SHA256 digest: workload %s exceeds size limit (4 > 2)", filepath.Join(s.dir, "exe")),
		},
		{
			name:        "success getting path and hashing process binary",
			trustDomain: "example.org",
			pid:         12,
			config:      "discover_workload_path = true",
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2000",
				"group:g2000",
				fmt.Sprintf("path:%s", filepath.Join(s.dir, "exe")),
				"sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
			},
			expectCode: codes.OK,
		},
		{
			name:        "success getting path and hashing process binary",
			trustDomain: "example.org",
			pid:         12,
			config:      "discover_workload_path = true",
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2000",
				"group:g2000",
				fmt.Sprintf("path:%s", filepath.Join(s.dir, "exe")),
				"sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
			},
			expectCode: codes.OK,
		},
		{
			name:        "success getting path, disabled hashing process binary",
			trustDomain: "example.org",
			pid:         12,
			config:      "discover_workload_path = true\nworkload_size_limit = -1",
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2000",
				"group:g2000",
				fmt.Sprintf("path:%s", filepath.Join(s.dir, "exe")),
			},
			expectCode: codes.OK,
		},
		{
			name:        "pid with supplementary gids",
			trustDomain: "example.org",
			pid:         13,
			selectorValues: []string{
				"uid:1000",
				"user:u1000",
				"gid:2000",
				"group:g2000",
				"supplementary_gid:2000",
				"supplementary_group:g2000",
				"supplementary_gid:2100",
				"supplementary_group:g2100",
				"supplementary_gid:2200",
				"supplementary_group:g2200",
				"supplementary_gid:2300",
				"supplementary_group:g2300",
			},
		},
		{
			name:        "fail to get supplementary gids",
			trustDomain: "example.org",
			pid:         14,
			expectCode:  codes.Internal,
			expectMsg:   "workloadattestor(unix): supplementary GIDs lookup: some error for PID 14",
		},
	}

	// prepare the "exe" for hashing
	s.writeFile("exe", []byte("data"))

	for _, testCase := range testCases {
		testCase := testCase
		s.T().Run(testCase.name, func(t *testing.T) {
			defer s.logHook.Reset()

			p := s.loadPlugin(t, testCase.trustDomain, testCase.config)
			selectors, err := p.Attest(ctx, testCase.pid)
			spiretest.RequireGRPCStatus(t, err, testCase.expectCode, testCase.expectMsg)
			if testCase.expectCode != codes.OK {
				require.Nil(t, selectors)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, selectors)
			var selectorValues []string
			for _, selector := range selectors {
				require.Equal(t, "unix", selector.Type)
				selectorValues = append(selectorValues, selector.Value)
			}

			require.Equal(t, testCase.selectorValues, selectorValues)
		})
	}
}

func (s *Suite) writeFile(path string, data []byte) {
	s.Require().NoError(os.WriteFile(filepath.Join(s.dir, path), data, 0o600))
}

func (s *Suite) loadPlugin(t *testing.T, trustDomain string, config string) workloadattestor.WorkloadAttestor {
	p := s.newPlugin()

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.Log(s.log),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
		}),
		plugintest.Configure(config))
	return v1
}

func (s *Suite) newPlugin() *Plugin {
	p := New()
	p.hooks.newProcess = func(pid int32) (processInfo, error) {
		return newFakeProcess(pid, s.dir), nil
	}
	p.hooks.lookupUserByID = fakeLookupUserByID
	p.hooks.lookupGroupByID = fakeLookupGroupByID
	return p
}

type fakeProcess struct {
	pid int32
	dir string
}

func (p fakeProcess) Uids() ([]uint32, error) {
	switch p.pid {
	case 1:
		return []uint32{}, nil
	case 2:
		return nil, fmt.Errorf("unable to get UIDs for PID %d", p.pid)
	case 3:
		return []uint32{1999}, nil
	case 4, 5, 6, 7, 9, 10, 11, 12, 13, 14:
		return []uint32{1000}, nil
	case 8:
		return []uint32{1000, 1100}, nil
	default:
		return nil, fmt.Errorf("unhandled uid test case %d", p.pid)
	}
}

func (p fakeProcess) Gids() ([]uint32, error) {
	switch p.pid {
	case 4:
		return []uint32{}, nil
	case 5:
		return nil, fmt.Errorf("unable to get GIDs for PID %d", p.pid)
	case 6:
		return []uint32{2999}, nil
	case 3, 7, 9, 10, 11, 12, 13, 14:
		return []uint32{2000}, nil
	case 8:
		return []uint32{2000, 2100}, nil
	default:
		return nil, fmt.Errorf("unhandled gid test case %d", p.pid)
	}
}

func (p fakeProcess) Groups() ([]string, error) {
	switch p.pid {
	case 13:
		return []string{"2000", "2100", "2200", "2300"}, nil
	case 14:
		return nil, fmt.Errorf("some error for PID %d", p.pid)
	default:
		return []string{}, nil
	}
}

func (p fakeProcess) Exe() (string, error) {
	switch p.pid {
	case 7, 8, 9:
		return "", fmt.Errorf("unable to get EXE for PID %d", p.pid)
	case 10:
		return filepath.Join(p.dir, "unreadable-exe"), nil
	case 11, 12:
		return filepath.Join(p.dir, "exe"), nil
	default:
		return "", fmt.Errorf("unhandled exe test case %d", p.pid)
	}
}

func (p fakeProcess) NamespacedExe() string {
	switch p.pid {
	case 11, 12:
		return filepath.Join(p.dir, "exe")
	default:
		return filepath.Join("/proc", strconv.Itoa(int(p.pid)), "unreadable-exe")
	}
}

func newFakeProcess(pid int32, dir string) processInfo {
	return fakeProcess{pid: pid, dir: dir}
}

func fakeLookupUserByID(uid string) (*user.User, error) {
	switch uid {
	case "1000":
		return &user.User{Username: "u1000"}, nil
	case "1100":
		return &user.User{Username: "u1100"}, nil
	default:
		return nil, fmt.Errorf("no user with UID %s", uid)
	}
}

func fakeLookupGroupByID(gid string) (*user.Group, error) {
	switch gid {
	case "2000":
		return &user.Group{Name: "g2000"}, nil
	case "2100":
		return &user.Group{Name: "g2100"}, nil
	case "2200":
		return &user.Group{Name: "g2200"}, nil
	case "2300":
		return &user.Group{Name: "g2300"}, nil
	default:
		return nil, fmt.Errorf("no group with GID %s", gid)
	}
}
