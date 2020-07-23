package middleware

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func callerContextFromContext(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "no peer information available")
	}

	ctx = rpccontext.WithCallerAddr(ctx, p.Addr)

	switch p.Addr.Network() {
	case "unix", "unixgram", "unixpacket":
		return rpccontext.WithLocalCaller(ctx), nil
	case "tcp", "tcp4", "tcp6":
		return tcpCallerContextFromPeer(ctx, p)
	default:
		return nil, status.Errorf(codes.Internal, "unsupported network %q", p.Addr.Network())
	}
}

func tcpCallerContextFromPeer(ctx context.Context, p *peer.Peer) (context.Context, error) {
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		// No TLS information. Return an unauthenticated TCP caller.
		return ctx, nil
	}

	// The connection state unfortunately does not have VerifiedChains set
	// because SPIFFE TLS does custom verification, i.e., Go's TLS stack only
	// sets VerifiedChains if it is the one to verify the chain of trust.
	switch {
	case !tlsInfo.State.HandshakeComplete:
		return nil, status.Error(codes.Internal, "TLS handshake is not complete")
	case len(tlsInfo.State.PeerCertificates) == 0:
		// No certificates. Return an unauthenticated TCP caller.
		return ctx, nil
	}

	x509SVID := tlsInfo.State.PeerCertificates[0]

	uris := x509SVID.URIs
	switch {
	case len(uris) == 0:
		return nil, status.Error(codes.Unauthenticated, "client certificate has no URI SAN")
	case len(uris) > 1:
		return nil, status.Error(codes.Unauthenticated, "client certificate has more than one URI SAN")
	}

	id, err := spiffeid.FromURI(uris[0])
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate has a malformed URI SAN: %v", err)
	}

	ctx = rpccontext.WithCallerID(ctx, id)
	ctx = rpccontext.WithCallerX509SVID(ctx, x509SVID)
	return ctx, nil
}
