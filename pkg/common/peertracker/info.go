package peertracker

import (
	"net"
)

const (
	authType = "spire-attestation"
)

type CallerInfo struct {
	Addr net.Addr
	PID  int32
	UID  uint32
	GID  uint32
}

type AuthInfo struct {
	Caller  CallerInfo
	Watcher Watcher
}

// AuthType returns the authentication type and allows us to
// conform to the gRPC AuthInfo interface
func (AuthInfo) AuthType() string {
	return authType
}
