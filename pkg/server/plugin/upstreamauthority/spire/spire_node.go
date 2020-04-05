package spireplugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/node"
)

func submitCSRUpstreamCA(ctx context.Context, nodeClient node.NodeClient, csr []byte) ([]*x509.Certificate, *bundleutil.Bundle, error) {
	resp, err := nodeClient.FetchX509CASVID(ctx, &node.FetchX509CASVIDRequest{
		Csr: csr,
	})
	if err != nil {
		return nil, nil, err
	}

	return getCertFromResponse(resp)
}

func getCertFromResponse(response *node.FetchX509CASVIDResponse) ([]*x509.Certificate, *bundleutil.Bundle, error) {
	if response.Svid == nil {
		return nil, nil, errors.New("response missing svid")
	}
	if response.Bundle == nil {
		return nil, nil, errors.New("missing bundle")
	}

	svid, err := x509.ParseCertificates(response.Svid.CertChain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid svid: %v", err)
	}

	bundle, err := bundleutil.BundleFromProto(response.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid bundle: %v", err)
	}

	return svid, bundle, nil
}

func (m *Plugin) newNodeClientConn(ctx context.Context, wCert []byte, wKey []byte, wBundle []byte) (*grpc.ClientConn, error) {
	return m.dialNodeAPI(ctx, wCert, wKey, wBundle)
}

func (m *Plugin) dialNodeAPI(ctx context.Context, wCert []byte, wKey []byte, wBundle []byte) (*grpc.ClientConn, error) {
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

func (m *Plugin) getGrpcTransportCreds(wCert []byte, wKey []byte, wBundle []byte) (credentials.TransportCredentials, error) {
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
