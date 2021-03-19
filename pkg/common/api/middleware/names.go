package middleware

import (
	"context"
	"strings"
	"sync"
	"unicode"

	"github.com/spiffe/spire/pkg/common/api"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
)

const (
	serverAPIPrefix = "spire.api.server."

	WorkloadAPIServiceName      = "SpiffeWorkloadAPI"
	WorkloadAPIServiceShortName = "WorkloadAPI"
	EnvoySDSv2ServiceName       = "envoy.service.discovery.v2.SecretDiscoveryService"
	EnvoySDSv2ServiceShortName  = "SDS.v2"
	EnvoySDSv3ServiceName       = "envoy.service.secret.v3.SecretDiscoveryService"
	EnvoySDSv3ServiceShortName  = "SDS.v3"
	HealthServiceName           = "grpc.health.v1.Health"
	HealthServiceShortName      = "Health"
)

var (
	serviceReplacer = strings.NewReplacer(
		serverAPIPrefix, "",
		WorkloadAPIServiceName, WorkloadAPIServiceShortName,
		EnvoySDSv2ServiceName, EnvoySDSv2ServiceShortName,
		EnvoySDSv3ServiceName, EnvoySDSv3ServiceShortName,
		HealthServiceName, HealthServiceShortName,
	)

	// namesCache caches parsed names
	namesCache sync.Map
)

// withNames returns a context and the names parsed out of the given full
// method. If the given context already has the parsed names, then those names
// are returned. Otherwise, a global cache is checked for the names, keyed by
// the full method. If present, the cached names are returned. Otherwise, the
// full method is parsed and the names cached and returned along with an
// embellished context.
func withNames(ctx context.Context, fullMethod string) (context.Context, api.Names) {
	names, ok := rpccontext.Names(ctx)
	if ok {
		return ctx, names
	}

	cached, ok := namesCache.Load(fullMethod)
	if ok {
		names = cached.(api.Names)
	} else {
		names = makeNames(fullMethod)
		namesCache.Store(fullMethod, names)
	}

	return rpccontext.WithNames(ctx, names), names
}

// makeNames parses a gRPC full method name into individual parts.  It expects
// the input to be well-formed since it gets its input from gRPC generated
// names. It will not panic if given bad input, but will not provide meaningful
// names.
func makeNames(fullMethod string) (names api.Names) {
	// Strip the leading slash. It should always be present in practice.
	if len(fullMethod) > 0 && fullMethod[0] == '/' {
		fullMethod = fullMethod[1:]
	}

	// Parse the slash separated service and method name. The separating slash
	// should always be present in practice.
	if slashIndex := strings.Index(fullMethod, "/"); slashIndex != -1 {
		names.RawService = fullMethod[0:slashIndex]
		names.Method = fullMethod[slashIndex+1:]
	}

	names.Service = serviceReplacer.Replace(names.RawService)
	names.MetricKey = append(names.MetricKey, strings.Split(names.Service, ".")...)
	names.MetricKey = append(names.MetricKey, names.Method)
	for i := range names.MetricKey {
		names.MetricKey[i] = metricKey(names.MetricKey[i])
	}
	return names
}

// metricKey converts an RPC service or method name into one appropriate for
// metrics use. It converts PascalCase into snake_case, also converting any
// non-alphanumeric rune into an underscore.
func metricKey(s string) string {
	in := []rune(s)
	var out []rune

	for i, r := range in {
		if !unicode.In(r, unicode.Letter, unicode.Number) {
			out = append(out, '_')
			continue
		}
		lr := unicode.ToLower(r)
		// Add an underscore if the current rune:
		// - is uppercase
		// - not the first rune
		// - is followed or preceded by a lowercase rune
		// - was not preceded by an underscore in the output
		if r != lr &&
			i > 0 &&
			(i+1) < len(in) &&
			(unicode.IsLower(in[i+1]) || unicode.IsLower(in[i-1])) &&
			out[len(out)-1] != '_' {
			out = append(out, '_')
		}
		out = append(out, lr)
	}
	return string(out)
}
