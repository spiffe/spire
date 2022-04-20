// Package peertracker handles attestation security for the SPIFFE Workload
// API. It does so in part by implementing the `net.Listener` interface and
// the gRPC credential interface, the functions of which are dependent on the
// underlying platform. Currently, UNIX domain sockets are supported on Linux,
// Darwin and the BSDs. Named pipes is supported on Windows.
//
// To accomplish the attestation security required by SPIFFE and SPIRE, this
// package provides process tracking - namely, exit detection. By using the
// included listener, `net.Conn`s can be cast back into the *peertracker.Conn
// type which allows access to caller information and liveness checks. By
// further utilizing the included gRPC credentials, this information can be
// extracted directly from the context by dependent handlers.
//
// Consumers that wish to use the included PID information for additional
// process interrogation should call IsAlive() following its use to ensure
// that the original caller is still alive and that the PID has not been
// reused.
package peertracker

import (
	"github.com/sirupsen/logrus"
)

type PeerTracker interface {
	Close()
	NewWatcher(CallerInfo) (Watcher, error)
}

type Watcher interface {
	Close()
	IsAlive() error
	PID() int32
}

// NewTracker creates a new platform-specific peer tracker. Close() must
// be called when done to release associated resources.
func NewTracker(log logrus.FieldLogger) (PeerTracker, error) {
	return newTracker(log)
}
