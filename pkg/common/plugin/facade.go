package plugin

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PrefixMessage prefixes the given message with plugin information. The prefix
// is only applied if it is not already applied.
func PrefixMessage(pluginInfo catalog.PluginInfo, message string) string {
	message, _ = prefixMessage(pluginInfo, message)
	return message
}

// Facade is embedded by plugin interface facade implementations as a
// convenient way to embed PluginInfo but also provide a set of convenient
// functions for embellishing and generating errors that have the plugin
// name prefixed.
type Facade struct {
	catalog.PluginInfo
	Log logrus.FieldLogger
}

// FixedFacade is a helper that creates a facade from fixed information, i.e.
// not the product of a loaded plugin.
func FixedFacade(pluginName, pluginType string, log logrus.FieldLogger) Facade {
	return Facade{
		PluginInfo: pluginInfo{
			pluginName: pluginName,
			pluginType: pluginType,
		},
		Log: log,
	}
}

// InitInfo partially satisfies the catalog.Facade interface
func (f *Facade) InitInfo(pluginInfo catalog.PluginInfo) {
	f.PluginInfo = pluginInfo
}

// InitLog partially satisfies the catalog.Facade interface
func (f *Facade) InitLog(log logrus.FieldLogger) {
	f.Log = log
}

// WrapError wraps a given error such that it will be prefixed with the plugin
// name. This method should be used by facade implementations to wrap errors
// that come out of plugin implementations.
func (f *Facade) WrapErr(err error) error {
	if err == nil {
		return nil
	}

	// Embellish the gRPC status with the prefix, if necessary.
	if st, ok := status.FromError(err); ok {
		// Care must be taken to preserve any status details. Therefore, the
		// proto is embellished directly and a new status created from that
		// proto.
		pb := st.Proto()
		if message, ok := prefixMessage(f, pb.Message); ok {
			pb.Message = message
			return status.FromProto(pb).Err()
		}
		return err
	}

	// Embellish the normal error with the prefix, if necessary. This is a
	// defensive measure since plugins go over gRPC.
	if message, ok := prefixMessage(f, err.Error()); ok {
		return &facadeError{wrapped: err, message: message}
	}

	return err
}

// Error creates a gRPC status with the given code and message. The message
// will be prefixed with the plugin name.
func (f *Facade) Error(code codes.Code, message string) error {
	return status.Error(code, messagePrefix(f)+message)
}

// Errorf creates a gRPC status with the given code and
// formatted message. The message will be prefixed with the plugin name.
func (f *Facade) Errorf(code codes.Code, format string, args ...any) error {
	return status.Errorf(code, messagePrefix(f)+format, args...)
}

func prefixMessage(pluginInfo catalog.PluginInfo, message string) (string, bool) {
	prefix := messagePrefix(pluginInfo)

	if strings.HasPrefix(message, prefix) {
		return message, false
	}

	oldPrefix := pluginInfo.Name() + ": "
	return prefix + strings.TrimPrefix(message, oldPrefix), true
}

func messagePrefix(pluginInfo catalog.PluginInfo) string {
	return strings.ToLower(pluginInfo.Type()) + "(" + pluginInfo.Name() + "): "
}

type facadeError struct {
	wrapped error
	message string
}

func (e *facadeError) Error() string {
	return e.message
}

func (e *facadeError) Unwrap() error {
	return e.wrapped
}

type pluginInfo struct {
	pluginName string
	pluginType string
}

func (info pluginInfo) Name() string {
	return info.pluginName
}

func (info pluginInfo) Type() string {
	return info.pluginType
}
