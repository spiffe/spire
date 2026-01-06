package witkey

import (
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromPluginProto(pb *plugintypes.WITKey) (WITKey, error) {
	return fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt, pb.Tainted)
}

func FromPluginProtos(pbs []*plugintypes.WITKey) ([]WITKey, error) {
	if pbs == nil {
		return nil, nil
	}
	witKeys := make([]WITKey, 0, len(pbs))
	for _, pb := range pbs {
		witKey, err := FromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		witKeys = append(witKeys, witKey)
	}
	return witKeys, nil
}

func ToPluginProto(witKey WITKey) (*plugintypes.WITKey, error) {
	id, publicKey, expiresAt, tainted, err := toProtoFields(witKey)
	if err != nil {
		return nil, err
	}
	return &plugintypes.WITKey{
		KeyId:     id,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
		Tainted:   tainted,
	}, nil
}

func ToPluginProtos(witKeys []WITKey) ([]*plugintypes.WITKey, error) {
	if witKeys == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.WITKey, 0, len(witKeys))
	for _, witKey := range witKeys {
		pb, err := ToPluginProto(witKey)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToPluginFromCommonProto(pb *common.PublicKey) (*plugintypes.WITKey, error) {
	witKey, err := FromCommonProto(pb)
	if err != nil {
		return nil, err
	}
	return ToPluginProto(witKey)
}

func ToPluginFromCommonProtos(pbs []*common.PublicKey) ([]*plugintypes.WITKey, error) {
	if pbs == nil {
		return nil, nil
	}
	witKeys := make([]*plugintypes.WITKey, 0, len(pbs))
	for _, pb := range pbs {
		witKey, err := ToPluginFromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		witKeys = append(witKeys, witKey)
	}
	return witKeys, nil
}

func ToPluginFromAPIProto(pb *apitypes.WITKey) (*plugintypes.WITKey, error) {
	if pb == nil {
		return nil, nil
	}

	witKey, err := fromProtoFields(pb.KeyId, pb.PublicKey, pb.ExpiresAt, pb.Tainted)
	if err != nil {
		return nil, err
	}

	return ToPluginProto(witKey)
}

func ToPluginFromAPIProtos(pbs []*apitypes.WITKey) ([]*plugintypes.WITKey, error) {
	if pbs == nil {
		return nil, nil
	}

	witAuthorities := make([]*plugintypes.WITKey, 0, len(pbs))
	for _, pb := range pbs {
		witKey, err := ToPluginFromAPIProto(pb)
		if err != nil {
			return nil, err
		}
		witAuthorities = append(witAuthorities, witKey)
	}

	return witAuthorities, nil
}
