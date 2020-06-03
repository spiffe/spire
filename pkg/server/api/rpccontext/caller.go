package rpccontext

import (
	"context"
	"crypto/x509"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
)

type callerAddrKey struct{}
type callerIDKey struct{}
type callerX509SVIDKey struct{}
type callerAdminEntriesKey struct{}
type callerDownstreamEntriesKey struct{}
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

// WithCallerAdminEntries returns a context with the given entries.
func WithCallerAdminEntries(ctx context.Context, entries []*types.Entry) context.Context {
	return context.WithValue(ctx, callerAdminEntriesKey{}, entries)
}

// CallerAdminEntries returns the admin entries for the caller. If the caller
// is not an admin caller, it returns false.
func CallerAdminEntries(ctx context.Context) ([]*types.Entry, bool) {
	entries, ok := ctx.Value(callerAdminEntriesKey{}).([]*types.Entry)
	return entries, ok
}

// CallerIsDownstream returns true if the caller is a downstream caller.
func CallerIsDownstream(ctx context.Context) bool {
	_, ok := CallerDownstreamEntries(ctx)
	return ok
}

// CallerIsAdmin returns true if the caller is an admin caller.
func CallerIsAdmin(ctx context.Context) bool {
	_, ok := CallerAdminEntries(ctx)
	return ok
}

// WithLocalCaller returns a context whether the caller is tagged as local.
func WithLocalCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerLocalTagKey{}, struct{}{})
}

// CallerIsLocal returns true if the caller is local.
func CallerIsLocal(ctx context.Context) bool {
	_, ok := ctx.Value(callerLocalTagKey{}).(struct{})
	return ok
}

// WithAgentCaller returns a context whether the caller is tagged as an agent.
func WithAgentCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerAgentTagKey{}, struct{}{})
}

// CallerIsAgent returns true if the caller is an agent.
func CallerIsAgent(ctx context.Context) bool {
	_, ok := ctx.Value(callerAgentTagKey{}).(struct{})
	return ok
}
