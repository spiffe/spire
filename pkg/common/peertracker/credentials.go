package peertracker

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type grpcCredentials struct{}

func NewCredentials() credentials.TransportCredentials {
	return &grpcCredentials{}
}

func (c *grpcCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn.Close()
	return conn, AuthInfo{}, ErrInvalidConnection
}

func (c *grpcCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	wrappedCon, ok := conn.(*Conn)
	if !ok {
		conn.Close()
		return conn, AuthInfo{}, ErrInvalidConnection
	}

	return wrappedCon, wrappedCon.Info, nil
}

func (c *grpcCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: authType,
		SecurityVersion:  "0.2",
		ServerName:       "spire-agent",
	}
}

func (c *grpcCredentials) Clone() credentials.TransportCredentials {
	return &(*c)
}

func (c *grpcCredentials) OverrideServerName(_ string) error {
	return nil
}

func WatcherFromContext(ctx context.Context) (Watcher, bool) {
	ai, ok := AuthInfoFromContext(ctx)
	if !ok {
		return nil, false
	}

	return ai.Watcher, true
}

func CallerFromContext(ctx context.Context) (CallerInfo, bool) {
	ai, ok := AuthInfoFromContext(ctx)
	if !ok {
		return CallerInfo{}, false
	}

	return ai.Caller, true
}

func AuthInfoFromContext(ctx context.Context) (AuthInfo, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return AuthInfo{}, false
	}

	ai, ok := peer.AuthInfo.(AuthInfo)
	return ai, ok
}
