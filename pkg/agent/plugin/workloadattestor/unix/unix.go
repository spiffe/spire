package unix

import (
	"errors"
	"fmt"

	"github.com/shirou/gopsutil/process"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

type UnixPlugin struct{}

const selectorType string = "unix"

func (UnixPlugin) Attest(req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p, err := process.NewProcess(req.Pid)
	resp := workloadattestor.AttestResponse{}

	if err != nil {
		return &resp, err
	}

	uids, err := p.Uids()

	if err != nil {
		return &resp, err
	}

	// Check if it's only the effective UID
	if len(uids) == 1 {
		resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("uid:%v", uids[0])})
	} else if len(uids) > 1 {
		// We got at least real and effective UIDs
		// use the effective UID
		resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("uid:%v", uids[1])})
	} else {
		return &resp, errors.New(fmt.Sprintf("Unable to get effective UID for PID: %v", req.Pid))
	}

	gids, err := p.Gids()

	if err != nil {
		return &resp, err
	}

	// Check if it's only the effective GID
	if len(gids) == 1 {
		resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("gid:%v", gids[0])})
	} else if len(gids) > 1 {
		// We got at least real and effective GIDs
		// use the effective GID
		resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("gid:%v", gids[1])})
	} else {
		return &resp, errors.New(fmt.Sprintf("Unable to get effective GID for PID: %v", req.Pid))
	}

	return &resp, nil
}

func (UnixPlugin) Configure(*spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (UnixPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() *UnixPlugin {
	return &UnixPlugin{}
}
