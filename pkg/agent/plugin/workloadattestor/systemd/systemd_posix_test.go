//go:build !windows
// +build !windows

package systemd

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ctx = context.Background()
)

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	log     logrus.FieldLogger
	logHook *test.Hook
}

func (s *Suite) SetupTest() {
	log, logHook := test.NewNullLogger()
	s.log = log
	s.logHook = logHook
}

func (s *Suite) TestAttest() {
	testCases := []struct {
		name           string
		pid            int
		selectorValues []string
		expectCode     codes.Code
		expectMsg      string
		expectLogs     []spiretest.LogEntry
	}{
		{
			name:           "get unit info",
			pid:            1,
			expectCode:     codes.OK,
			selectorValues: []string{"id:fake.service", "fragment_path:/org/freedesktop/systemd1/unit/fake_2eservice"},
		},
		{
			name:       "fail to get unit id",
			pid:        2,
			expectCode: codes.Unknown,
			expectMsg:  "workloadattestor(systemd): failed to get unit id for pid 2: rpc error: code = Internal desc = unknown process",
		},
		{
			name:       "fail to get fragment path",
			pid:        3,
			expectCode: codes.Unknown,
			expectMsg:  "workloadattestor(systemd): failed to get unit fragment path for pid 3: rpc error: code = Internal desc = unknown process",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		s.T().Run(testCase.name, func(t *testing.T) {
			defer s.logHook.Reset()

			p := s.loadPlugin(t)
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
				require.Equal(t, "systemd", selector.Type)
				selectorValues = append(selectorValues, selector.Value)
			}

			require.Equal(t, testCase.selectorValues, selectorValues)
			spiretest.AssertLogs(t, s.logHook.AllEntries(), testCase.expectLogs)
		})
	}
}

func (s *Suite) loadPlugin(t *testing.T) workloadattestor.WorkloadAttestor {
	p := s.newPlugin()

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.Log(s.log))
	return v1
}

func (s *Suite) newPlugin() *Plugin {
	p := New()
	p.getUnitInfo = func(ctx context.Context, pid uint) (unitInfo, error) {
		return newFakeUnit(pid), nil
	}
	return p
}

type fakeUnit struct {
	pid uint
}

func (u fakeUnit) Id() (string, error) {
	switch u.pid {
	case 1, 3:
		return "fake.service", nil
	case 2:
		return "", status.Errorf(codes.Internal, "unknown process")
	default:
		return "", status.Errorf(codes.Internal, "unhandled unit Id test case %d", u.pid)
	}
}

func (u fakeUnit) FragmentPath() (string, error) {
	switch u.pid {
	case 1, 2:
		return "/org/freedesktop/systemd1/unit/fake_2eservice", nil
	case 3:
		return "", status.Errorf(codes.Internal, "unknown process")
	default:
		return "", fmt.Errorf("unhandled unit FragmentPath test case %d", u.pid)
	}
}

func newFakeUnit(pid uint) unitInfo {
	return fakeUnit{pid}
}
