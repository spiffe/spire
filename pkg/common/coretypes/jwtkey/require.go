package jwtkey

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func RequireFromCommonProto(pb *common.PublicKey) JWTKey {
	out, err := FromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireFromCommonProtos(pbs []*common.PublicKey) []JWTKey {
	out, err := FromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireFromPluginProto(pb *plugintypes.JWTKey) JWTKey {
	out, err := FromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireFromPluginProtos(pbs []*plugintypes.JWTKey) []JWTKey {
	out, err := FromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProto(pb *plugintypes.JWTKey) *common.PublicKey {
	out, err := ToCommonFromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProtos(pbs []*plugintypes.JWTKey) []*common.PublicKey {
	out, err := ToCommonFromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonProto(jwtKey JWTKey) *common.PublicKey {
	out, err := ToCommonProto(jwtKey)
	panicOnError(err)
	return out
}

func RequireToCommonProtos(jwtKeys []JWTKey) []*common.PublicKey {
	out, err := ToCommonProtos(jwtKeys)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProto(pb *common.PublicKey) *plugintypes.JWTKey {
	out, err := ToPluginFromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProtos(pbs []*common.PublicKey) []*plugintypes.JWTKey {
	out, err := ToPluginFromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToPluginProto(jwtKey JWTKey) *plugintypes.JWTKey {
	out, err := ToPluginProto(jwtKey)
	panicOnError(err)
	return out
}

func RequireToPluginProtos(jwtKeys []JWTKey) []*plugintypes.JWTKey {
	out, err := ToPluginProtos(jwtKeys)
	panicOnError(err)
	return out
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
