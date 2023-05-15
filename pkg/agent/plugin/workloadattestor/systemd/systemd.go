package systemd

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "systemd"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
