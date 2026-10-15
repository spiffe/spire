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

// TrackerConfig holds optional configuration for the peer tracker.
type TrackerConfig struct {
	// AllowUIDMismatch, when true, enables an additional check in IsAlive()
	// for UID and GID mismatches that cannot be explained by user-namespace
	// remapping. When the flag is set and the connecting process holds
	// CAP_SETUID (or CAP_SETGID) in its effective capability set, the
	// mismatch is accepted with a warning log.
	//
	// This is required when workloads run inside sandbox container runtimes
	// such as gVisor (runsc) configured with --host-uds=open. In that
	// configuration the gofer process holds CAP_SETUID/CAP_SETGID so it can
	// call setresuid on the connecting thread to impersonate the workload
	// before forwarding the connect() to the host socket; /proc/<pid>/status
	// still shows the gofer running as root.
	//
	// A UID or GID mismatch where the process does NOT hold the corresponding
	// capability is still treated as an error (possible PID recycling). The
	// primary TOCTOU safeguards (ReadDirent + starttime comparison) remain
	// active regardless of this setting.
	AllowUIDMismatch bool
}

// NewTracker creates a new platform-specific peer tracker. Close() must
// be called when done to release associated resources.
func NewTracker(log logrus.FieldLogger) (PeerTracker, error) {
	return newTrackerWithConfig(log, TrackerConfig{})
}

// NewTrackerWithConfig creates a new platform-specific peer tracker with
// the provided configuration. Close() must be called when done.
func NewTrackerWithConfig(log logrus.FieldLogger, config TrackerConfig) (PeerTracker, error) {
	return newTrackerWithConfig(log, config)
}
