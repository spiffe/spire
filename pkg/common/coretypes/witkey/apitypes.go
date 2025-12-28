package witkey

import (
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
)

func ToAPIProto(witKey WITKey) (*apitypes.WITKey, error) {
	id, publicKey, expiresAt, tainted, err := toProtoFields(witKey)
	if err != nil {
		return nil, err
	}

	return &apitypes.WITKey{
		KeyId:     id,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
		Tainted:   tainted,
	}, nil
}

func ToAPIFromPluginProto(pb *plugintypes.WITKey) (*apitypes.WITKey, error) {
	if pb == nil {
		return nil, nil
	}

	witKey, err := fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt, pb.Tainted)
	if err != nil {
		return nil, err
	}

	return ToAPIProto(witKey)
}
