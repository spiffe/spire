package bundle

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func RequireToCommonFromPluginProto(pb *plugintypes.Bundle) *common.Bundle {
	out, err := ToCommonFromPluginProto(pb)
	panicOnError(err)
	return out
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
