package unix

import (
	"context"
	"fmt"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/proto/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

func init() {
	newProcess = newFakeProcess
	lookupUserById = fakeLookupUserById
	lookupGroupById = fakeLookupGroupById
}

var (
	ctx = context.Background()
)

func TestUnix_Attest(t *testing.T) {
	testCases := []struct {
		name      string
		pid       int32
		err       string
		selectors []string
	}{
		{name: "pid with no uids", pid: 1, err: "unix: unable to get effective UID for PID 1"},
		{name: "fail to get uids", pid: 2, err: "unix: unable to get UIDs for PID 2"},
		{name: "user lookup fails", pid: 3, err: "unix: no user with UID 1999"},
		{name: "pid with no gids", pid: 4, err: "unix: unable to get effective GID for PID 4"},
		{name: "fail to get gids", pid: 5, err: "unix: unable to get GIDs for PID 5"},
		{name: "group lookup fails", pid: 6, err: "unix: no group with GID 2999"},
		{name: "primary user and gid", pid: 7, selectors: []string{"uid:1000", "user:u1000", "gid:2000", "group:g2000"}},
		{name: "effective user and gid", pid: 8, selectors: []string{"uid:1100", "user:u1100", "gid:2100", "group:g2100"}},
	}

	plugin := New()
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resp, err := plugin.Attest(ctx, &workloadattestor.AttestRequest{
				Pid: testCase.pid,
			})
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			var selectors []string
			for _, selector := range resp.Selectors {
				require.Equal(t, "unix", selector.Type)
				selectors = append(selectors, selector.Value)
			}
			require.Equal(t, testCase.selectors, selectors)
		})
	}
}

func TestUnix_Configure(t *testing.T) {
	plugin := New()
	data, e := plugin.Configure(ctx, &spi.ConfigureRequest{})
	assert.Equal(t, &spi.ConfigureResponse{}, data)
	assert.Equal(t, nil, e)
}

func TestUnix_GetPluginInfo(t *testing.T) {
	plugin := New()
	data, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
	assert.Equal(t, nil, e)
}

type fakeProcess struct {
	pid int32
}

func (p fakeProcess) Uids() ([]int32, error) {
	switch p.pid {
	case 1:
		return []int32{}, nil
	case 2:
		return nil, fmt.Errorf("unable to get UIDs for PID %d", p.pid)
	case 3:
		return []int32{1999}, nil
	case 4, 5, 6, 7:
		return []int32{1000}, nil
	case 8:
		return []int32{1000, 1100}, nil
	default:
		return nil, fmt.Errorf("unhandled uid test case %d", p.pid)
	}
}

func (p fakeProcess) Gids() ([]int32, error) {
	switch p.pid {
	case 4:
		return []int32{}, nil
	case 5:
		return nil, fmt.Errorf("unable to get GIDs for PID %d", p.pid)
	case 6:
		return []int32{2999}, nil
	case 7:
		return []int32{2000}, nil
	case 8:
		return []int32{2000, 2100}, nil
	default:
		return nil, fmt.Errorf("unhandled gid test case %d", p.pid)
	}
}

func newFakeProcess(pid int32) (processInfo, error) {
	return fakeProcess{pid: pid}, nil
}

func fakeLookupUserById(uid string) (*user.User, error) {
	switch uid {
	case "1000":
		return &user.User{Username: "u1000"}, nil
	case "1100":
		return &user.User{Username: "u1100"}, nil
	default:
		return nil, fmt.Errorf("no user with UID %s", uid)
	}
}

func fakeLookupGroupById(gid string) (*user.Group, error) {
	switch gid {
	case "2000":
		return &user.Group{Name: "g2000"}, nil
	case "2100":
		return &user.Group{Name: "g2100"}, nil
	default:
		return nil, fmt.Errorf("no group with GID %s", gid)
	}
}
