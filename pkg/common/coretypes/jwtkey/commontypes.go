package jwtkey

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromCommonProto(pb *common.PublicKey) (JWTKey, error) {
	return fromProtoFields(pb.Kid, pb.PkixBytes, pb.NotAfter)
}

func FromCommonProtos(pbs []*common.PublicKey) ([]JWTKey, error) {
	if pbs == nil {
		return nil, nil
	}
	jwtKeys := make([]JWTKey, 0, len(pbs))
	for _, pb := range pbs {
		jwtKey, err := FromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		jwtKeys = append(jwtKeys, jwtKey)
	}
	return jwtKeys, nil
}

func ToCommonProto(jwtKey JWTKey) (*common.PublicKey, error) {
	id, publicKey, expiresAt, err := toProtoFields(jwtKey)
	if err != nil {
		return nil, err
	}
	return &common.PublicKey{
		Kid:       id,
		PkixBytes: publicKey,
		NotAfter:  expiresAt,
	}, nil
}

func ToCommonProtos(jwtKeys []JWTKey) ([]*common.PublicKey, error) {
	if jwtKeys == nil {
		return nil, nil
	}
	pbs := make([]*common.PublicKey, 0, len(jwtKeys))
	for _, jwtKey := range jwtKeys {
		pb, err := ToCommonProto(jwtKey)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToCommonFromPluginProto(pb *plugintypes.JWTKey) (*common.PublicKey, error) {
	jwtKey, err := FromPluginProto(pb)
	if err != nil {
		return nil, err
	}
	return ToCommonProto(jwtKey)
}

func ToCommonFromPluginProtos(pbs []*plugintypes.JWTKey) ([]*common.PublicKey, error) {
	if pbs == nil {
		return nil, nil
	}
	jwtKeys := make([]*common.PublicKey, 0, len(pbs))
	for _, pb := range pbs {
		jwtKey, err := ToCommonFromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		jwtKeys = append(jwtKeys, jwtKey)
	}
	return jwtKeys, nil
}
