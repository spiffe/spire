package x509certificate

import (
	"crypto/x509"

	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromPluginProto(pb *plugintypes.X509Certificate) (*x509.Certificate, error) {
	return fromProtoFields(pb.Asn1)
}

func FromPluginProtos(pbs []*plugintypes.X509Certificate) ([]*x509.Certificate, error) {
	if pbs == nil {
		return nil, nil
	}
	x509Certificates := make([]*x509.Certificate, 0, len(pbs))
	for _, pb := range pbs {
		x509Certificate, err := FromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		x509Certificates = append(x509Certificates, x509Certificate)
	}
	return x509Certificates, nil
}

func ToPluginProto(x509Certificate *x509.Certificate) (*plugintypes.X509Certificate, error) {
	asn1, err := toProtoFields(x509Certificate)
	if err != nil {
		return nil, err
	}
	return &plugintypes.X509Certificate{
		Asn1: asn1,
	}, nil
}

func ToPluginProtos(x509Certificates []*x509.Certificate) ([]*plugintypes.X509Certificate, error) {
	if x509Certificates == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.X509Certificate, 0, len(x509Certificates))
	for _, x509Certificate := range x509Certificates {
		pb, err := ToPluginProto(x509Certificate)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToPluginFromCommonProtos(pbs []*common.Certificate) ([]*plugintypes.X509Certificate, error) {
	certs, err := FromCommonProtos(pbs)
	if err != nil {
		return nil, err
	}
	return ToPluginProtos(certs)
}

func RawFromPluginProto(pb *plugintypes.X509Certificate) ([]byte, error) {
	return rawFromProtoFields(pb.Asn1)
}

func RawFromPluginProtos(pbs []*plugintypes.X509Certificate) ([][]byte, error) {
	if pbs == nil {
		return nil, nil
	}
	rawX509Certificates := make([][]byte, 0, len(pbs))
	for _, pb := range pbs {
		rawX509Certificate, err := RawFromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		rawX509Certificates = append(rawX509Certificates, rawX509Certificate)
	}
	return rawX509Certificates, nil
}

func RawToPluginProto(rawX509Certificate []byte) (*plugintypes.X509Certificate, error) {
	asn1, err := rawToProtoFields(rawX509Certificate)
	if err != nil {
		return nil, err
	}
	return &plugintypes.X509Certificate{
		Asn1: asn1,
	}, nil
}

func RawToPluginProtos(rawX509Certificates [][]byte) ([]*plugintypes.X509Certificate, error) {
	if rawX509Certificates == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.X509Certificate, 0, len(rawX509Certificates))
	for _, rawX509Certificate := range rawX509Certificates {
		pb, err := RawToPluginProto(rawX509Certificate)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func ToPluginFromAPIProto(pb *apitypes.X509Certificate) (*plugintypes.X509Certificate, error) {
	if pb == nil {
		return nil, nil
	}

	asn1, err := rawFromProtoFields(pb.Asn1)
	if err != nil {
		return nil, err
	}
	return &plugintypes.X509Certificate{
		Asn1: asn1,
	}, nil
}

func ToPluginFromAPIProtos(pbs []*apitypes.X509Certificate) ([]*plugintypes.X509Certificate, error) {
	if pbs == nil {
		return nil, nil
	}
	var x509Authorities []*plugintypes.X509Certificate
	for _, pb := range pbs {
		authority, err := ToPluginFromAPIProto(pb)
		if err != nil {
			return nil, err
		}
		x509Authorities = append(x509Authorities, authority)
	}

	return x509Authorities, nil
}
