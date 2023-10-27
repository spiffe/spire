//go:build !windows

package middleware

import (
	"github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setFields sets audit log fields specific to the Unix platforms.
func setFields(p *process.Process, fields logrus.Fields) error {
	uID, err := getUID(p)
	if err != nil {
		return err
	}
	fields[telemetry.CallerUID] = uID

	gID, err := getGID(p)
	if err != nil {
		return err
	}
	fields[telemetry.CallerGID] = gID

	return nil
}

func getUID(p *process.Process) (int32, error) {
	uids, err := p.Uids()
	if err != nil {
		return 0, status.Errorf(codes.Internal, "failed UIDs lookup: %v", err)
	}

	switch len(uids) {
	case 0:
		return 0, status.Error(codes.Internal, "failed UIDs lookup: no UIDs for process")
	case 1:
		return uids[0], nil
	default:
		return uids[1], nil
	}
}

func getGID(p *process.Process) (int32, error) {
	gids, err := p.Gids()
	if err != nil {
		return 0, status.Errorf(codes.Internal, "failed GIDs lookup: %v", err)
	}

	switch len(gids) {
	case 0:
		return 0, status.Error(codes.Internal, "failed GIDs lookup: no GIDs for process")
	case 1:
		return gids[0], nil
	default:
		return gids[1], nil
	}
}
