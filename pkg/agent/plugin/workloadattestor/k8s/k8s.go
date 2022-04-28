package k8s

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "k8s"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
