package api

import (
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire-next/types"
)

type X509SVID struct {
	ID        spiffeid.ID
	CertChain []*x509.Certificate
	ExpiresAt time.Time
}

func (s *X509SVID) ToProto() *types.X509SVID {
	return &types.X509SVID{
		Id: &types.SPIFFEID{
			TrustDomain: s.ID.TrustDomain().String(),
			Path:        s.ID.Path(),
		},
		CertChain: x509util.RawCertsFromCertificates(s.CertChain),
		ExpiresAt: s.ExpiresAt.Unix(),
	}
}

