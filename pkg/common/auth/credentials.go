package auth

import (
	"net"

	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
)

// grpcCredentials implements the GRPC Credential interface. It reads the
// network type to invoke the correct PID resolution logic, based on the
// transport protocol, and bakes the information into the context.
type grpcCredentials struct{}

func (c *grpcCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	info := CallerInfo{Err: ErrInvalidConnection}
	return conn, info, nil
}

func (c *grpcCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	var info CallerInfo

	// Invoke the appropriate PID resolutionl logic based
	// on transport type
	switch conn.RemoteAddr().Network() {
	case "unix":
		info = FromUDSConn(conn)
	default:
		info = CallerInfo{Err: ErrUnsupportedTransport}
	}

	// Returning an error here hangs the connection
	return conn, info, nil
}

func (c *grpcCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: authType,
		SecurityVersion:  "0.1",
		ServerName:       "spire-agent",
	}
}

func (c *grpcCredentials) Clone() credentials.TransportCredentials {
	return &(*c)
}

func (c *grpcCredentials) OverrideServerName(_ string) error {
	return nil
}

func NewCredentials() credentials.TransportCredentials {
	return &grpcCredentials{}
}
