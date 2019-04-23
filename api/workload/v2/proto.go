package workload

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/spire/proto/spire/api/workload"
)

func protoToX509SVIDs(protoSVIDs *workload.X509SVIDResponse) (*X509SVIDs, error) {
	if len(protoSVIDs.GetSvids()) == 0 {
		return nil, errors.New("workload response contains no svids")
	}

	svids := new(X509SVIDs)
	for _, protoSVID := range protoSVIDs.GetSvids() {
		svid, err := protoToX509SVID(protoSVID)
		if err != nil {
			// TODO(tjulian): Probably support partial success
			return nil, fmt.Errorf("failed to parse svid for spiffe id %q: %v", protoSVID.GetSpiffeId(), err)
		}
		svids.SVIDs = append(svids.SVIDs, svid)
	}

	return svids, nil
}

func protoToX509SVID(svid *workload.X509SVID) (*X509SVID, error) {
	certificates, err := x509.ParseCertificates(svid.GetX509Svid())
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, errors.New("no certificates found")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(svid.GetX509SvidKey())
	if err != nil {
		return nil, err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is type %T, not crypto.Signer", privateKey)
	}
	trustBundle, err := x509.ParseCertificates(svid.GetBundle())
	if err != nil {
		return nil, err
	}
	trustBundlePool := x509.NewCertPool()
	for _, cert := range trustBundle {
		trustBundlePool.AddCert(cert)
	}
	return &X509SVID{
		SPIFFEID:        svid.GetSpiffeId(),
		PrivateKey:      signer,
		Certificates:    certificates,
		TrustBundle:     trustBundle,
		TrustBundlePool: trustBundlePool,
	}, nil
}
