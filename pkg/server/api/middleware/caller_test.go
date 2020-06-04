package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestCallerContextFromContext(t *testing.T) {
	workloadID := spiffeid.Must("example.org", "workload")
	workloadX509SVID := &x509.Certificate{URIs: []*url.URL{workloadID.URL()}}

	ipPeer := &peer.Peer{
		Addr: &net.IPAddr{},
	}
	unixPeer := &peer.Peer{
		Addr: &net.UnixAddr{Net: "unix"},
	}
	unixgramPeer := &peer.Peer{
		Addr: &net.UnixAddr{Net: "unixgram"},
	}
	unixpacketPeer := &peer.Peer{
		Addr: &net.UnixAddr{Net: "unixpacket"},
	}
	tcpPeer := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
	}
	tlsPeer := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
			},
		},
	}
	tlsPeerIncompleteHandshake := &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{},
	}
	mtlsPeer := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{workloadX509SVID},
			},
		},
	}
	mtlsPeerNoURISAN := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{{}},
			},
		},
	}
	mtlsPeerMoreThanOneURISAN := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{{URIs: []*url.URL{{}, {}}}},
			},
		},
	}
	mtlsPeerMalformedURISAN := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1")},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{{URIs: []*url.URL{{Scheme: "http"}}}},
			},
		},
	}

	for _, tt := range []struct {
		name                 string
		peer                 *peer.Peer
		expectCode           codes.Code
		expectMsg            string
		expectIsLocal        bool
		expectCallerID       spiffeid.ID
		expectCallerX509SVID *x509.Certificate
	}{
		{
			name:       "no peer",
			expectCode: codes.Internal,
			expectMsg:  "no peer information available",
		},
		{
			name:       "not unix or tcp",
			peer:       ipPeer,
			expectCode: codes.Internal,
			expectMsg:  `unsupported network "ip"`,
		},
		{
			name:          "unix peer",
			peer:          unixPeer,
			expectCode:    codes.OK,
			expectIsLocal: true,
		},
		{
			name:          "unixgram peer",
			peer:          unixgramPeer,
			expectCode:    codes.OK,
			expectIsLocal: true,
		},
		{
			name:          "unixpacket peer",
			peer:          unixpacketPeer,
			expectCode:    codes.OK,
			expectIsLocal: true,
		},
		{
			name:       "tcp peer",
			peer:       tcpPeer,
			expectCode: codes.OK,
		},
		{
			name:       "tls peer",
			peer:       tlsPeer,
			expectCode: codes.OK,
		},
		{
			name:       "tls peer incomplete handshake",
			peer:       tlsPeerIncompleteHandshake,
			expectCode: codes.Internal,
			expectMsg:  "TLS handshake is not complete",
		},
		{
			name:                 "mtls peer",
			peer:                 mtlsPeer,
			expectCode:           codes.OK,
			expectCallerID:       workloadID,
			expectCallerX509SVID: workloadX509SVID,
		},
		{
			name:       "mtls peer with no URI SAN",
			peer:       mtlsPeerNoURISAN,
			expectCode: codes.Unauthenticated,
			expectMsg:  "client certificate has no URI SAN",
		},
		{
			name:       "mtls peer with more than one URI SAN",
			peer:       mtlsPeerMoreThanOneURISAN,
			expectCode: codes.Unauthenticated,
			expectMsg:  "client certificate has more than one URI SAN",
		},
		{
			name:       "mtls peer with malformed URI SAN",
			peer:       mtlsPeerMalformedURISAN,
			expectCode: codes.Unauthenticated,
			expectMsg:  "client certificate has a malformed URI SAN: spiffeid: invalid scheme",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctxIn := context.Background()
			if tt.peer != nil {
				ctxIn = peer.NewContext(ctxIn, tt.peer)
			}

			ctxOut, err := callerContextFromContext(ctxIn)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				assert.Nil(t, ctxOut)
				return
			}

			assert.Equal(t, tt.peer.Addr, rpccontext.CallerAddr(ctxOut))

			assert.Equal(t, tt.expectIsLocal, rpccontext.CallerIsLocal(ctxOut))

			callerID, ok := rpccontext.CallerID(ctxOut)
			assert.Equal(t, !tt.expectCallerID.IsZero(), ok)
			assert.Equal(t, tt.expectCallerID, callerID)

			callerX509SVID, ok := rpccontext.CallerX509SVID(ctxOut)
			assert.Equal(t, tt.expectCallerX509SVID != nil, ok)
			assert.Equal(t, tt.expectCallerX509SVID, callerX509SVID)
		})
	}
}
