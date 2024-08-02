package x509certificate

import (
	"crypto/x509"

	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
)

// TODO: may we call it Authority?
// TODO: may we add subjectKeyID?
type X509Authority struct {
	Certificate *x509.Certificate
	Tainted     bool
}

func ToX509AuthorityFromPluginProtos(pbs []*plugintypes.X509Certificate) ([]*X509Authority, error) {
	var authorities []*X509Authority
	for _, pb := range pbs {
		authority, err := ToX509AuthorityFromPluginProto(pb)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, authority)
	}

	return authorities, nil
}

func ToX509AuthorityFromPluginProto(pb *plugintypes.X509Certificate) (*X509Authority, error) {
	cert, err := fromProtoFields(pb.Asn1)
	if err != nil {
		return nil, err
	}

	return &X509Authority{
		Certificate: cert,
		Tainted:     pb.Tainted,
	}, nil
}
