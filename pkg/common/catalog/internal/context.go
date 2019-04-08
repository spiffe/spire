package internal

import "context"

type pluginNameKey struct{}

func PluginNameFromHostServiceContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(pluginNameKey{}).(string)
	return name, ok
}

func WithPluginName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, pluginNameKey{}, name)
}
