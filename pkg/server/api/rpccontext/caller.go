package rpccontext

import (
	"context"
	"crypto/x509"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

type callerAddrKey struct{}
type callerIDKey struct{}
type callerX509SVIDKey struct{}
type callerDownstreamEntriesKey struct{}
type callerAdminTagKey struct{}
type callerLocalTagKey struct{}
type callerAgentTagKey struct{}

// WithCallerAddr returns a context with the given address.
func WithCallerAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, callerAddrKey{}, addr)
}

// CallerAddr returns the caller address.
func CallerAddr(ctx context.Context) net.Addr {
	return ctx.Value(callerAddrKey{}).(net.Addr)
}

// WithCallerID returns a context with the given ID.
func WithCallerID(ctx context.Context, id spiffeid.ID) context.Context {
	return context.WithValue(ctx, callerIDKey{}, id)
}

// CallerID returns the caller ID, if available.
func CallerID(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(callerIDKey{}).(spiffeid.ID)
	return id, ok
}

// WithCallerX509SVID returns a context with the given X509SVID.
func WithCallerX509SVID(ctx context.Context, x509SVID *x509.Certificate) context.Context {
	return context.WithValue(ctx, callerX509SVIDKey{}, x509SVID)
}

// CallerX509SVID returns the caller X509SVID, if available.
func CallerX509SVID(ctx context.Context) (*x509.Certificate, bool) {
	x509SVID, ok := ctx.Value(callerX509SVIDKey{}).(*x509.Certificate)
	return x509SVID, ok
}

// WithCallerDownstreamEntries returns a context with the given entries.
func WithCallerDownstreamEntries(ctx context.Context, entries []*types.Entry) context.Context {
	return context.WithValue(ctx, callerDownstreamEntriesKey{}, entries)
}

// CallerDownstreamEntries returns the downstream entries for the caller. If the caller is not
// a downstream caller, it returns false.
func CallerDownstreamEntries(ctx context.Context) ([]*types.Entry, bool) {
	entries, ok := ctx.Value(callerDownstreamEntriesKey{}).([]*types.Entry)
	return entries, ok
}

// CallerIsDownstream returns true if the caller is a downstream caller.
func CallerIsDownstream(ctx context.Context) bool {
	_, ok := CallerDownstreamEntries(ctx)
	return ok
}

// WithAdminCaller returns a context where the caller is tagged as an admin.
func WithAdminCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerAdminTagKey{}, struct{}{})
}

// CallerIsAdmin returns true if the caller is an admin.
func CallerIsAdmin(ctx context.Context) bool {
	_, ok := ctx.Value(callerAdminTagKey{}).(struct{})
	return ok
}

// WithLocalCaller returns a context where the caller is tagged as local.
func WithLocalCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerLocalTagKey{}, struct{}{})
}

// CallerIsLocal returns true if the caller is local.
func CallerIsLocal(ctx context.Context) bool {
	_, ok := ctx.Value(callerLocalTagKey{}).(struct{})
	return ok
}

// WithAgentCaller returns a context where the caller is tagged as an agent.
func WithAgentCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerAgentTagKey{}, struct{}{})
}

// CallerIsAgent returns true if the caller is an agent.
func CallerIsAgent(ctx context.Context) bool {
	_, ok := ctx.Value(callerAgentTagKey{}).(struct{})
	return ok
}
