//go:build !windows

package util

import (
	"context"
	"flag"
	"fmt"
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
	flags.StringVar(&a.instance, "instance", "", "Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).")
}

func (a *Adapter) getGRPCAddr() (string, error) {
	tpl := os.Getenv("SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE")
	sock := os.Getenv("SPIRE_SERVER_PRIVATE_SOCKET")
	if a.instance != "" {
		if tpl == "" {
			return "", fmt.Errorf("you must define %s to use the instance flag", "SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE")
		}
		if !strings.Contains(tpl, "%i") {
			return "", fmt.Errorf("failed to find %%i in %s", "SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE")
		}
	}
	socketPath := DefaultSocketPath
	switch {
	case a.socketPath != DefaultSocketPath:
		socketPath = a.socketPath
	case a.instance != "":
		socketPath = strings.ReplaceAll(tpl, "%i", a.instance)
	case sock != "":
		socketPath = sock
	}

	// When grpc-go deprecated grpc.DialContext() in favor of grpc.NewClient(),
	// they made a breaking change to always use the DNS resolver, even when overriding the context dialer.
	// This is problematic for clients that do not use DNS for address resolution and don't set a resolver in the address.
	// As a workaround, use the passthrough resolver to prevent using the DNS resolver.
	// More context can be found in this issue: https://github.com/grpc/grpc-go/issues/1786#issuecomment-2114124036
	return "unix:" + socketPath, nil
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	// This is an ugly workaround to circumvent grpc-go needing us to provide the resolver in the address
	// in order to bypass DNS lookup, which is not relevant in the case of CLI invocation.
	// More context can be found in this issue: https://github.com/grpc/grpc-go/issues/1786#issuecomment-2114124036
	socketPathAddr := strings.TrimPrefix(addr, "unix:")
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPathAddr)
}
