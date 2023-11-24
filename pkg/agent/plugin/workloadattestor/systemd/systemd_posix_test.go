//go:build !windows

package systemd

import (
	"context"
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
			name:       "fail to get unit info",
			pid:        2,
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(systemd): unknown process",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		log, logHook := test.NewNullLogger()
		t.Run(testCase.name, func(t *testing.T) {
			p := loadPlugin(t, log)
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
			spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)
		})
	}
}

func loadPlugin(t *testing.T, log logrus.FieldLogger) workloadattestor.WorkloadAttestor {
	p := newPlugin()

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1, plugintest.Log(log))
	return v1
}

func newPlugin() *Plugin {
	p := New()
	p.getUnitInfo = func(ctx context.Context, p *Plugin, pid uint) (*DBusUnitInfo, error) {
		switch pid {
		case 1:
			return &DBusUnitInfo{"fake.service", "/org/freedesktop/systemd1/unit/fake_2eservice"}, nil
		case 2:
			return nil, status.Errorf(codes.Internal, "unknown process")
		default:
			return nil, status.Errorf(codes.Internal, "unhandled unit Id test case %d", pid)
		}
	}
	return p
}
