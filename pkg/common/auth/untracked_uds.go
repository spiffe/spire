package auth

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

// UntrackedUDSCredentials returns credentials for UDS servers that rely solely
// on file permissions for access control. If the caller information (e.g. PID,
// UID, GID) is in any way used for further access control or authorization
// decisions, these credentials SHOULD NOT be used. The peertracker package
// should instead be used, which provides mitigation against PID reuse and
// related attacks.
func UntrackedUDSCredentials() credentials.TransportCredentials {
	return untrackedUDSCredentials{}
}

func IsUntrackedUDSAuth(authInfo credentials.AuthInfo) bool {
	_, ok := authInfo.(UntrackedUDSAuthInfo)
	return ok
}

type UntrackedUDSAuthInfo struct{}

func (UntrackedUDSAuthInfo) AuthType() string { return "untracked-uds" }

type untrackedUDSCredentials struct{}

func (c untrackedUDSCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn.Close()
	return conn, nil, errors.New("untracked UDS credentials do not implement the client handshake")
}

func (c untrackedUDSCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, UntrackedUDSAuthInfo{}, nil
}

func (c untrackedUDSCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{}
}

func (c untrackedUDSCredentials) Clone() credentials.TransportCredentials {
	return untrackedUDSCredentials{}
}

func (c untrackedUDSCredentials) OverrideServerName(_ string) error {
	return nil
}
