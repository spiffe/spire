package witkey

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func RequireFromCommonProto(pb *common.PublicKey) WITKey {
	out, err := FromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireFromCommonProtos(pbs []*common.PublicKey) []WITKey {
	out, err := FromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireFromPluginProto(pb *plugintypes.WITKey) WITKey {
	out, err := FromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireFromPluginProtos(pbs []*plugintypes.WITKey) []WITKey {
	out, err := FromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProto(pb *plugintypes.WITKey) *common.PublicKey {
	out, err := ToCommonFromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProtos(pbs []*plugintypes.WITKey) []*common.PublicKey {
	out, err := ToCommonFromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonProto(witKey WITKey) *common.PublicKey {
	out, err := ToCommonProto(witKey)
	panicOnError(err)
	return out
}

func RequireToCommonProtos(witKeys []WITKey) []*common.PublicKey {
	out, err := ToCommonProtos(witKeys)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProto(pb *common.PublicKey) *plugintypes.WITKey {
	out, err := ToPluginFromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProtos(pbs []*common.PublicKey) []*plugintypes.WITKey {
	out, err := ToPluginFromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToPluginProto(witKey WITKey) *plugintypes.WITKey {
	out, err := ToPluginProto(witKey)
	panicOnError(err)
	return out
}

func RequireToPluginProtos(witKeys []WITKey) []*plugintypes.WITKey {
	out, err := ToPluginProtos(witKeys)
	panicOnError(err)
	return out
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
