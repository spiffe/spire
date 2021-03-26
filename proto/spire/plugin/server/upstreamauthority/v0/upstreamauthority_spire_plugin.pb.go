// Code generated by protoc-gen-go-spire. DO NOT EDIT.

package upstreamauthorityv0

import (
	pluginsdk "github.com/spiffe/spire-plugin-sdk/pluginsdk"
	grpc "google.golang.org/grpc"
)

func UpstreamAuthorityPluginServer(server UpstreamAuthorityServer) pluginsdk.PluginServer {
	return upstreamAuthorityPluginServer{UpstreamAuthorityServer: server}
}

type upstreamAuthorityPluginServer struct {
	UpstreamAuthorityServer
}

func (s upstreamAuthorityPluginServer) Type() string {
	return "UpstreamAuthority"
}

func (s upstreamAuthorityPluginServer) GRPCServiceName() string {
	return "spire.server.upstreamauthority.UpstreamAuthority"
}

func (s upstreamAuthorityPluginServer) RegisterServer(server *grpc.Server) interface{} {
	RegisterUpstreamAuthorityServer(server, s.UpstreamAuthorityServer)
	return s.UpstreamAuthorityServer
}

type UpstreamAuthorityPluginClient struct {
	UpstreamAuthorityClient
}

func (s UpstreamAuthorityPluginClient) Type() string {
	return "UpstreamAuthority"
}

func (c *UpstreamAuthorityPluginClient) IsInitialized() bool {
	return c.UpstreamAuthorityClient != nil
}

func (c *UpstreamAuthorityPluginClient) GRPCServiceName() string {
	return "spire.server.upstreamauthority.UpstreamAuthority"
}

func (c *UpstreamAuthorityPluginClient) InitClient(conn grpc.ClientConnInterface) interface{} {
	c.UpstreamAuthorityClient = NewUpstreamAuthorityClient(conn)
	return c.UpstreamAuthorityClient
}
