package x509certificate

import (
	"crypto/x509"

	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromCommonProto(pb *common.Certificate) (*x509.Certificate, error) {
	return fromProtoFields(pb.DerBytes)
}

func FromCommonProtos(pbs []*common.Certificate) ([]*x509.Certificate, error) {
	if pbs == nil {
		return nil, nil
	}
	x509Certificates := make([]*x509.Certificate, 0, len(pbs))
	for _, pb := range pbs {
		x509Certificate, err := FromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		x509Certificates = append(x509Certificates, x509Certificate)
	}
	return x509Certificates, nil
}

func ToCommonProto(x509Certificate *x509.Certificate) (*common.Certificate, error) {
	asn1, err := toProtoFields(x509Certificate)
	if err != nil {
		return nil, err
	}
	return &common.Certificate{
		DerBytes: asn1,
	}, nil
}

func ToCommonProtos(x509Certificates []*x509.Certificate) ([]*common.Certificate, error) {
	if x509Certificates == nil {
		return nil, nil
	}
	pbs := make([]*common.Certificate, 0, len(x509Certificates))
	for _, x509Certificate := range x509Certificates {
		pb, err := ToCommonProto(x509Certificate)
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

func RawFromCommonProto(pb *common.Certificate) ([]byte, error) {
	return rawFromProtoFields(pb.DerBytes)
}

func RawFromCommonProtos(pbs []*common.Certificate) ([][]byte, error) {
	if pbs == nil {
		return nil, nil
	}
	rawX509Certificates := make([][]byte, 0, len(pbs))
	for _, pb := range pbs {
		rawX509Certificate, err := RawFromCommonProto(pb)
		if err != nil {
			return nil, err
		}
		rawX509Certificates = append(rawX509Certificates, rawX509Certificate)
	}
	return rawX509Certificates, nil
}

func RawToCommonProto(rawX509Certificate []byte) (*common.Certificate, error) {
	asn1, err := rawToProtoFields(rawX509Certificate)
	if err != nil {
		return nil, err
	}
	return &common.Certificate{
		DerBytes: asn1,
	}, nil
}

func RawToCommonProtos(rawX509Certificates [][]byte) ([]*common.Certificate, error) {
	if rawX509Certificates == nil {
		return nil, nil
	}
	pbs := make([]*common.Certificate, 0, len(rawX509Certificates))
	for _, rawX509Certificate := range rawX509Certificates {
		pb, err := RawToCommonProto(rawX509Certificate)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}
