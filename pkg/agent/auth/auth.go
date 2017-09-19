/*
The auth package handles GRPC transport "security" for the workload API. It
does so by implementing the GRPC credential interface, the function of which
is dependent on the underlying transport method. Currently, only UNIX domain
sockets are supported.

In the context of the Workload API, we are looking to retrieve the PID of the
caller. To do this, two steps are required: 1) use one of the types provided
in this package as the GRPC transport credentials, and 2) use the provided
top-level helpers to pull the PID out of a supplied GRPC context.
*/
package auth

import (
	"errors"
	"net"

	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	authType = "spire-attestation"
)

var (
	ErrInvalidConnection    = errors.New("invalid connection")
	ErrUnsupportedPlatform  = errors.New("unsupported host OS")
	ErrUnsupportedTransport = errors.New("unsupported network transport")
)

type CallerInfo struct {
	Addr net.Addr
	PID  int32

	// Bailing out during gRPC transport negotiation can lead to
	// "weird" behavior, and it may also be unclear as to why the
	// connection failed to establish. Instead, allow the connection
	// through, and populate Err if we were unable to resolve a PID.
	Err error
}

func (CallerInfo) AuthType() string {
	return authType
}

// CallerFromContext pulls CallerInfo out of a gRPC context, assuming
// that our custom Credentials implementation was used during creation
// of the gRPC server.
func CallerFromContext(ctx context.Context) (CallerInfo, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return CallerInfo{}, false
	}
	return CallerFromAuthInfo(peer.AuthInfo)
}

// CallerFromAuthInfo attempts to cast a gRPC AuthInfo struct to a CallerInfo
// struct. It then returns CallerInfo, assuming that the cast was successful. The
// cast will fail if our custom Credentials implementation was not used during
// creation of the gRPC server.
func CallerFromAuthInfo(ai credentials.AuthInfo) (CallerInfo, bool) {
	if ai, ok := ai.(CallerInfo); ok {
		return ai, true
	}
	return CallerInfo{}, false
}
