package x509certificate

import (
	"crypto/x509"

	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func FromPluginProto(pb *plugintypes.X509Certificate) (*X509Authority, error) {
	return fromProtoFields(pb.Asn1, pb.Tainted)
}

func FromPluginProtos(pbs []*plugintypes.X509Certificate) ([]*X509Authority, error) {
	if pbs == nil {
		return nil, nil
	}
	x509Certificates := make([]*X509Authority, 0, len(pbs))
	for _, pb := range pbs {
		x509Certificate, err := FromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		x509Certificates = append(x509Certificates, x509Certificate)
	}
	return x509Certificates, nil
}

func ToPluginProto(x509Authority *X509Authority) (*plugintypes.X509Certificate, error) {
	asn1, tainted, err := toProtoFields(x509Authority)
	if err != nil {
		return nil, err
	}
	return &plugintypes.X509Certificate{
		Asn1:    asn1,
		Tainted: tainted,
	}, nil
}

func ToPluginProtos(x509Authorities []*X509Authority) ([]*plugintypes.X509Certificate, error) {
	if x509Authorities == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.X509Certificate, 0, len(x509Authorities))
	for _, x509Certificate := range x509Authorities {
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

func ToPluginFromCertificates(x509Certificates []*x509.Certificate) ([]*plugintypes.X509Certificate, error) {
	if x509Certificates == nil {
		return nil, nil
	}
	pbs := make([]*plugintypes.X509Certificate, 0, len(x509Certificates))
	for _, eachCert := range x509Certificates {
		pb, err := ToPluginFromCertificate(eachCert)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}

	return pbs, nil
}

func ToPluginFromCertificate(x509Certificate *x509.Certificate) (*plugintypes.X509Certificate, error) {
	if err := validateX509Certificate(x509Certificate); err != nil {
		return nil, err
	}

	return &plugintypes.X509Certificate{
		Asn1:    x509Certificate.Raw,
		Tainted: false,
	}, nil
}

func ToPluginFromAPIProto(pb *apitypes.X509Certificate) (*plugintypes.X509Certificate, error) {
	if pb == nil {
		return nil, nil
	}

	x509Authority, err := fromProtoFields(pb.Asn1, pb.Tainted)
	if err != nil {
		return nil, err
	}
	return &plugintypes.X509Certificate{
		Asn1:    x509Authority.Certificate.Raw,
		Tainted: x509Authority.Tainted,
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
