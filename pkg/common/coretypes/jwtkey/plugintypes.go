package jwtkey

import (
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromPluginProto(pb *plugintypes.JWTKey) (JWTKey, error) {
	return fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt, pb.Tainted)
}

func FromPluginProtos(pbs []*plugintypes.JWTKey) ([]JWTKey, error) {
	if pbs == nil {
		return nil, nil
	}
	jwtKeys := make([]JWTKey, 0, len(pbs))
	for _, pb := range pbs {
		jwtKey, err := FromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		jwtKeys = append(jwtKeys, jwtKey)
	}
	return jwtKeys, nil
}

func ToPluginProto(jwtKey JWTKey) (*plugintypes.JWTKey, error) {
	id, publicKey, expiresAt, tainted, err := toProtoFields(jwtKey)
	if err != nil {
		return nil, err
	}
	return &plugintypes.JWTKey{
		KeyId:     id,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
		Tainted:   tainted,
	}, nil
}

func ToPluginProtos(jwtKeys []JWTKey) ([]*plugintypes.JWTKey, error) {
	if jwtKeys == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.JWTKey, 0, len(jwtKeys))
	for _, jwtKey := range jwtKeys {
		pb, err := ToPluginProto(jwtKey)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToPluginFromCommonProto(pb *common.PublicKey) (*plugintypes.JWTKey, error) {
	jwtKey, err := FromCommonProto(pb)
	if err != nil {
		return nil, err
	}
	return ToPluginProto(jwtKey)
}

func ToPluginFromCommonProtos(pbs []*common.PublicKey) ([]*plugintypes.JWTKey, error) {
	if pbs == nil {
		return nil, nil
	}
	jwtKeys := make([]*plugintypes.JWTKey, 0, len(pbs))
	for _, pb := range pbs {
		jwtKey, err := ToPluginFromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		jwtKeys = append(jwtKeys, jwtKey)
	}
	return jwtKeys, nil
}

func ToPluginFromAPIProto(pb *apitypes.JWTKey) (*plugintypes.JWTKey, error) {
	if pb == nil {
		return nil, nil
	}

	jwtKey, err := fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt, pb.Tainted)
	if err != nil {
		return nil, err
	}

	return ToPluginProto(jwtKey)
}

func ToPluginFromAPIProtos(pbs []*apitypes.JWTKey) ([]*plugintypes.JWTKey, error) {
	if pbs == nil {
		return nil, nil
	}

	jwtAuthorities := make([]*plugintypes.JWTKey, 0, len(pbs))
	for _, pb := range pbs {
		jwtKey, err := ToPluginFromAPIProto(pb)
		if err != nil {
			return nil, err
		}
		jwtAuthorities = append(jwtAuthorities, jwtKey)
	}

	return jwtAuthorities, nil
}
