package manager

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (m *manager) newGRPCConn(svid *x509.Certificate, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: m.bundleAsCertPool(),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(m.serverAddr.String(), dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *manager) fetchUpdate(csrs [][]byte) (regEntries map[string]*common.RegistrationEntry, svids map[string]*node.Svid) {
	err := m.fetchSVIDStream.Send(&node.FetchSVIDRequest{Csrs: csrs})
	if err != nil {
		// TODO: should we try to create a new stream?
		m.shutdown(err)
		return
	}

	regEntries = map[string]*common.RegistrationEntry{}
	svids = map[string]*node.Svid{}
	var lastBundle []byte
	for {
		resp, err := m.fetchSVIDStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// TODO: should we try to create a new stream?
			m.shutdown(err)
			return nil, nil
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			regEntryKey := util.DeriveRegEntryhash(re)
			regEntries[regEntryKey] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		lastBundle = resp.SvidUpdate.Bundle
	}

	if lastBundle != nil {
		bundle, err := x509.ParseCertificates(lastBundle)
		if err != nil {
			m.shutdown(err)
			return nil, nil
		}
		m.setBundle(bundle)
	}

	return
}
