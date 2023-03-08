package rotator

import (
	"errors"

	"github.com/spiffe/spire/pkg/common/health"
)

// TODO: What would be a good threshold number?
const failedRotationThreshold = 10

type caSyncHealth struct {
	m *Rotator
}

func (h *caSyncHealth) CheckHealth() health.State {
	// Readiness and liveness will be checked by manager's ability to
	// rotate for a certain threshold.
	live := true
	ready := true
	var rotationErr error
	if h.m.failedRotationResult() > failedRotationThreshold {
		live = false
		ready = false
		rotationErr = errors.New("rotations exceed the threshold number of failures")
	}

	return health.State{
		Live:  live,
		Ready: ready,
		ReadyDetails: managerHealthDetails{
			RotationErr: errString(rotationErr),
		},
		LiveDetails: managerHealthDetails{
			RotationErr: errString(rotationErr),
		},
	}
}

type managerHealthDetails struct {
	RotationErr string `json:"rotation_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
