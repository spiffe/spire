package jwtkey

import (
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
)

func ToAPIProto(jwtKey JWTKey) (*apitypes.JWTKey, error) {
	id, publicKey, expiresAt, err := toProtoFields(jwtKey)
	if err != nil {
		return nil, err
	}

	return &apitypes.JWTKey{
		KeyId:     id,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
	}, nil
}

func ToAPIFromPluginProto(pb *plugintypes.JWTKey) (*apitypes.JWTKey, error) {
	if pb == nil {
		return nil, nil
	}

	jwtKey, err := fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt)
	if err != nil {
		return nil, err
	}

	return ToAPIProto(jwtKey)
}
