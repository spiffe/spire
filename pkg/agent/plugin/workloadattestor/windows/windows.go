package windows

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "windows"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
