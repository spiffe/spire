package x509certificate

import (
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromCommonProto(pb *common.Certificate) (*X509Authority, error) {
	return fromProtoFields(pb.DerBytes, pb.TaintedKey)
}

func FromCommonProtos(pbs []*common.Certificate) ([]*X509Authority, error) {
	if pbs == nil {
		return nil, nil
	}
	x509Certificates := make([]*X509Authority, 0, len(pbs))
	for _, pb := range pbs {
		x509Certificate, err := FromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		x509Certificates = append(x509Certificates, x509Certificate)
	}
	return x509Certificates, nil
}

func ToCommonProto(x509Authority *X509Authority) (*common.Certificate, error) {
	asn1, tainted, err := toProtoFields(x509Authority)
	if err != nil {
		return nil, err
	}
	return &common.Certificate{
		DerBytes:   asn1,
		TaintedKey: tainted,
	}, nil
}

func ToCommonProtos(x509Authorities []*X509Authority) ([]*common.Certificate, error) {
	if x509Authorities == nil {
		return nil, nil
	}
	pbs := make([]*common.Certificate, 0, len(x509Authorities))
	for _, x509Authority := range x509Authorities {
		pb, err := ToCommonProto(x509Authority)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToCommonFromPluginProtos(pbs []*plugintypes.X509Certificate) ([]*common.Certificate, error) {
	certs, err := FromPluginProtos(pbs)
	if err != nil {
		return nil, err
	}
	return ToCommonProtos(certs)
}
