package unix

import (
	"context"
	"fmt"
	"os/user"

	"github.com/shirou/gopsutil/process"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
)

const (
	selectorType = "unix"
)

var (
	unixErr = errs.Class("unix")

	// hooks for tests
	newProcess      = func(pid int32) (processInfo, error) { return process.NewProcess(pid) }
	lookupUserById  = user.LookupId
	lookupGroupById = user.LookupGroupId
)

type processInfo interface {
	Uids() ([]int32, error)
	Gids() ([]int32, error)
}

type UnixPlugin struct{}

func New() *UnixPlugin {
	return &UnixPlugin{}
}

func (p *UnixPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	uid, err := getUid(req.Pid)
	if err != nil {
		return nil, err
	}

	user, err := getUserName(uid)
	if err != nil {
		return nil, err
	}

	gid, err := getGid(req.Pid)
	if err != nil {
		return nil, err
	}

	group, err := getGroupName(gid)
	if err != nil {
		return nil, err
	}

	return &workloadattestor.AttestResponse{
		Selectors: []*common.Selector{
			makeSelector("uid", uid),
			makeSelector("user", user),
			makeSelector("gid", gid),
			makeSelector("group", group),
		},
	}, nil
}

func (p *UnixPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p *UnixPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func getUid(pid int32) (string, error) {
	proc, err := newProcess(pid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	uids, err := proc.Uids()
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	switch len(uids) {
	case 0:
		return "", unixErr.New("unable to get effective UID for PID %d", pid)
	case 1:
		return fmt.Sprint(uids[0]), nil
	default:
		return fmt.Sprint(uids[1]), nil
	}
}

func getUserName(uid string) (string, error) {
	u, err := lookupUserById(uid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}
	return u.Username, nil
}

func getGid(pid int32) (string, error) {
	proc, err := newProcess(pid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	gids, err := proc.Gids()
	if err != nil {
		return "", unixErr.Wrap(err)
	}

	switch len(gids) {
	case 0:
		return "", unixErr.New("unable to get effective GID for PID %d", pid)
	case 1:
		return fmt.Sprint(gids[0]), nil
	default:
		return fmt.Sprint(gids[1]), nil
	}
}

func getGroupName(gid string) (string, error) {
	g, err := lookupGroupById(gid)
	if err != nil {
		return "", unixErr.Wrap(err)
	}
	return g.Name, nil
}

func makeSelector(kind, value string) *common.Selector {
	return &common.Selector{
		Type:  selectorType,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}
