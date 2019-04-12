package spireplugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/node"
)

func (m *spirePlugin) submitCSRUpstreamCA(ctx context.Context, nodeClient node.NodeClient, csr []byte) ([]*x509.Certificate, *bundleutil.Bundle, error) {
	nodeRequest := &node.FetchX509SVIDRequest{
		Csrs: [][]byte{csr},
	}

	stream, err := nodeClient.FetchX509SVID(ctx)
	if err != nil {
		return nil, nil, err
	}
	err = stream.Send(nodeRequest)
	if err != nil {
		return nil, nil, err
	}

	stream.CloseSend()

	nodeResponse, err := stream.Recv()
	if err != nil {
		return nil, nil, err
	}

	return m.getCertFromResponse(nodeResponse)
}

func (m *spirePlugin) getCertFromResponse(response *node.FetchX509SVIDResponse) ([]*x509.Certificate, *bundleutil.Bundle, error) {
	if response.SvidUpdate == nil {
		return nil, nil, errors.New("response missing svid update")
	}
	if len(response.SvidUpdate.Svids) < 1 {
		return nil, nil, errors.New("no svid received")
	}

	svidMsg, ok := response.SvidUpdate.Svids[m.trustDomain.String()]
	if !ok {
		return nil, nil, fmt.Errorf("no svid for %v received", m.trustDomain.String())
	}

	svid, err := x509.ParseCertificates(svidMsg.CertChain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid svid: %v", err)
	}

	if response.SvidUpdate.Bundles == nil {
		return nil, nil, errors.New("missing bundles")
	}

	bundleProto := response.SvidUpdate.Bundles[m.trustDomain.String()]
	if bundleProto == nil {
		return nil, nil, errors.New("missing bundle")
	}

	bundle, err := bundleutil.BundleFromProto(bundleProto)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid bundle: %v", err)
	}

	return svid, bundle, nil
}

func (m *spirePlugin) newNodeClientConn(ctx context.Context, wCert []byte, wKey []byte, wBundle []byte) (*grpc.ClientConn, error) {
	return m.dialNodeAPI(ctx, wCert, wKey, wBundle)
}

func (m *spirePlugin) dialNodeAPI(ctx context.Context, wCert []byte, wKey []byte, wBundle []byte) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // TODO: Make this timeout configurable?
	defer cancel()

	serverAddr := fmt.Sprintf("%s:%s", m.config.ServerAddr, m.config.ServerPort)
	tc, err := m.getGrpcTransportCreds(wCert, wKey, wBundle)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(ctx, serverAddr, grpc.WithTransportCredentials(tc))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *spirePlugin) getGrpcTransportCreds(wCert []byte, wKey []byte, wBundle []byte) (credentials.TransportCredentials, error) {
	var tlsCerts []tls.Certificate
	var tlsConfig *tls.Config
	var err error

	svid, err := x509.ParseCertificates(wCert)
	if err != nil {
		return credentials.NewTLS(nil), err
	}

	key, err := x509.ParsePKCS8PrivateKey(wKey)
	if err != nil {
		return credentials.NewTLS(nil), err
	}

	bundle, err := x509.ParseCertificates(wBundle)
	if err != nil {
		return credentials.NewTLS(nil), err
	}

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{idutil.ServerID(m.trustDomain.Host)},
		TrustRoots: util.NewCertPool(bundle...),
	}

	tlsCert := tls.Certificate{PrivateKey: key}
	for _, cert := range svid {
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}
	tlsCerts = append(tlsCerts, tlsCert)
	tlsConfig = spiffePeer.NewTLSConfig(tlsCerts)
	return credentials.NewTLS(tlsConfig), nil
}
