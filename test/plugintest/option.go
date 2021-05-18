package plugintest

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire/pkg/common/catalog"
)

// Option is plugin test option
type Option interface {
	setOption(config *config)
}

type optionFunc func(conf *config)

func (fn optionFunc) setOption(conf *config) {
	fn(conf)
}

// Log sets the logger for the plugin.
func Log(log logrus.FieldLogger) Option {
	return optionFunc(func(conf *config) {
		conf.builtInConfig.Log = log
	})
}

// Services sets the services also implemented by the plugin.
func Services(serviceFacades ...catalog.Facade) Option {
	return optionFunc(func(conf *config) {
		conf.serviceFacades = serviceFacades
	})
}

// HostServices sets the host services the host will offer to the plugin.
func HostServices(hostServices ...pluginsdk.ServiceServer) Option {
	return optionFunc(func(conf *config) {
		conf.builtInConfig.HostServices = hostServices
	})
}

// CoreConfig provides the core configuration passed to the plugin when
// configured.
func CoreConfig(coreConfig catalog.CoreConfig) Option {
	return optionFunc(func(conf *config) {
		conf.doConfigure = true
		conf.coreConfig = coreConfig
	})
}

// Configure provides raw configuration to the plugin for configuration.
func Configure(plainConfig string) Option {
	return optionFunc(func(conf *config) {
		conf.doConfigure = true
		conf.plainConfig = &plainConfig
	})
}

// Configuref provides a formatted string to the plugin for configuration.
func Configuref(format string, args ...interface{}) Option {
	return Configure(fmt.Sprintf(format, args...))
}

// ConfigureJSON marshals the given object and passes the resulting JSON to
// the plugin for configuration.
func ConfigureJSON(jsonConfig interface{}) Option {
	return optionFunc(func(conf *config) {
		conf.doConfigure = true
		conf.jsonConfig = jsonConfig
	})
}

// CaptureLoadError captures the error encountered during loading. If loading
// fails, and this option is not provided, the test will fail.
func CaptureLoadError(errp *error) Option {
	return optionFunc(func(conf *config) {
		conf.loadErr = errp
	})
}

// CaptureLoadError captures the error encountered during configuration. If
// configuration fails, and this option is not provided, the test will fail.
func CaptureConfigureError(errp *error) Option {
	return optionFunc(func(conf *config) {
		conf.doConfigure = true
		conf.configureErr = errp
	})
}
