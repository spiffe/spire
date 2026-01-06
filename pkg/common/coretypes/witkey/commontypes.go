package witkey

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromCommonProto(pb *common.PublicKey) (WITKey, error) {
	return fromProtoFields(pb.Kid, pb.PkixBytes, pb.NotAfter, pb.TaintedKey)
}

func FromCommonProtos(pbs []*common.PublicKey) ([]WITKey, error) {
	if pbs == nil {
		return nil, nil
	}
	witKeys := make([]WITKey, 0, len(pbs))
	for _, pb := range pbs {
		witKey, err := FromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		witKeys = append(witKeys, witKey)
	}
	return witKeys, nil
}

func ToCommonProto(witKey WITKey) (*common.PublicKey, error) {
	id, publicKey, expiresAt, tainted, err := toProtoFields(witKey)
	if err != nil {
		return nil, err
	}
	return &common.PublicKey{
		Kid:        id,
		PkixBytes:  publicKey,
		NotAfter:   expiresAt,
		TaintedKey: tainted,
	}, nil
}

func ToCommonProtos(witKeys []WITKey) ([]*common.PublicKey, error) {
	if witKeys == nil {
		return nil, nil
	}
	pbs := make([]*common.PublicKey, 0, len(witKeys))
	for _, witKey := range witKeys {
		pb, err := ToCommonProto(witKey)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToCommonFromPluginProto(pb *plugintypes.WITKey) (*common.PublicKey, error) {
	witKey, err := FromPluginProto(pb)
	if err != nil {
		return nil, err
	}
	return ToCommonProto(witKey)
}

func ToCommonFromPluginProtos(pbs []*plugintypes.WITKey) ([]*common.PublicKey, error) {
	if pbs == nil {
		return nil, nil
	}
	witKeys := make([]*common.PublicKey, 0, len(pbs))
	for _, pb := range pbs {
		witKey, err := ToCommonFromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		witKeys = append(witKeys, witKey)
	}
	return witKeys, nil
}
