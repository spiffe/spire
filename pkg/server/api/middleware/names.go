package middleware

import (
	"context"
	"strings"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
)

func withNames(ctx context.Context, fullMethod string) (context.Context, api.Names) {
	names, ok := rpccontext.Names(ctx)
	if !ok {
		names = makeNames(fullMethod)
		ctx = rpccontext.WithNames(ctx, names)
	}
	return ctx, names
}

// makeNameEntry parses a gRPC full method name into individual parts with
// the common server API prefix stripped off. If the full method does not
// have the common server API prefix, the leading slash is simply removed.
// It expects the input to be well-formed since it gets its input from gRPC
// generated names. It will not panic if given bad input, but will not provide
// meaningful names.
func makeNames(fullMethod string) (names api.Names) {
	// Trim off the common prefix
	fullMethod = strings.TrimPrefix(fullMethod, serverAPIPrefix)

	// If the full method doesn't have the common prefix for whatever reason,
	// remove the leading slash.
	if len(fullMethod) > 0 && fullMethod[0] == '/' {
		fullMethod = fullMethod[1:]
	}

	// Parse the slash separated service and method name
	if slashIndex := strings.Index(fullMethod, "/"); slashIndex != -1 {
		names.Service = fullMethod[0:slashIndex]
		names.Method = fullMethod[slashIndex+1:]
	}
	return names
}
