//go:build !windows

package util

import (
	"context"
	"flag"
	"net"
	"os"
	"strings"
)

type adapterOS struct {
	socketPath string
	instance   string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.socketPath, "socketPath", DefaultSocketPath, "Path to the SPIRE Server API socket")
	flags.StringVar(&a.instance, "instance", "", "Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.")
}

func (a *Adapter) getGRPCAddr() string {
	if a.socketPath == "" {
		a.socketPath = DefaultSocketPath
	}

	tpl := os.Getenv("SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE")
	if tpl != "" && strings.Contains(tpl, "%i") {
		if a.instance == "" {
			a.instance = "main"
		}
		if a.socketPath == DefaultSocketPath {
			a.socketPath = strings.ReplaceAll(tpl, "%i", a.instance)
		}
	}

	// When grpc-go deprecated grpc.DialContext() in favor of grpc.NewClient(),
	// they made a breaking change to always use the DNS resolver, even when overriding the context dialer.
	// This is problematic for clients that do not use DNS for address resolution and don't set a resolver in the address.
	// As a workaround, use the passthrough resolver to prevent using the DNS resolver.
	// More context can be found in this issue: https://github.com/grpc/grpc-go/issues/1786#issuecomment-2114124036
	return "unix:" + a.socketPath
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	// This is an ugly workaround to circumvent grpc-go needing us to provide the resolver in the address
	// in order to bypass DNS lookup, which is not relevant in the case of CLI invocation.
	// More context can be found in this issue: https://github.com/grpc/grpc-go/issues/1786#issuecomment-2114124036
	socketPathAddr := strings.TrimPrefix(addr, "unix:")
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPathAddr)
}
