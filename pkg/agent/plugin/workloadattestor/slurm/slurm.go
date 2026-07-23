package slurm

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "slurm"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
