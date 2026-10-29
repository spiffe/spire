package manager

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type jwtRequests struct {
	mu         sync.Mutex
	active     map[string]*jwtRequest
	authorized map[cache.JWTRegistration]struct{}
}

type jwtRequest struct {
	done         chan struct{}
	cancel       context.CancelFunc
	waiters      int
	svid         *client.JWTSVID
	err          error
	registration cache.JWTRegistration
}

func (m *manager) fetchCoordinatedJWTSVID(ctx context.Context, entry *common.RegistrationEntry, audience []string) (*client.JWTSVID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := spiffeid.FromString(entry.SpiffeId); err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	audience = slices.Clone(audience)
	slices.Sort(audience)
	audience = slices.Compact(audience)

	key := cache.JWTSVIDRequestKey(entry, audience)
	registration := cache.RegistrationForJWT(entry)
	m.jwtRequests.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.jwtRequests.mu.Unlock()
		return nil, err
	}
	if m.jwtRequests.authorized != nil {
		if _, ok := m.jwtRequests.authorized[registration]; !ok {
			m.jwtRequests.mu.Unlock()
			return nil, status.Error(codes.PermissionDenied, "registration is no longer authorized")
		}
	}
	cached, ok := m.jwtCache.GetJWTSVIDForRequest(key)
	now := m.clk.Now()
	useCached := ok && !m.c.RotationStrategy.JWTSVIDExpiresSoon(cached, now)
	if err := ctx.Err(); err != nil {
		m.jwtRequests.mu.Unlock()
		return nil, err
	}
	if useCached {
		m.jwtRequests.mu.Unlock()
		return cached, nil
	}
	request := m.jwtRequests.active[key]
	if request == nil {
		upstreamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		request = &jwtRequest{done: make(chan struct{}), cancel: cancel, registration: registration}
		m.jwtRequests.active[key] = request
		hasCacheHit := ok && !rotationutil.JWTSVIDExpired(cached, now)
		go m.signCoordinatedJWT(upstreamCtx, request, key, entry.EntryId, audience, hasCacheHit)
	}
	request.waiters++
	m.jwtRequests.mu.Unlock()

	select {
	case <-ctx.Done():
		m.jwtRequests.mu.Lock()
		if m.jwtRequests.active[key] == request {
			request.waiters--
			if request.waiters == 0 {
				delete(m.jwtRequests.active, key)
				request.cancel()
			}
		}
		m.jwtRequests.mu.Unlock()
		return nil, ctx.Err()
	case <-request.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return copyJWTSVID(request.svid), request.err
	}
}

func (m *manager) signCoordinatedJWT(ctx context.Context, request *jwtRequest, key, entryID string, audience []string, hasCacheHit bool) {
	defer request.cancel()
	svid, _, err := m.client.NewJWTSVID(ctx, entryID, audience, hasCacheHit)

	m.jwtRequests.mu.Lock()
	defer m.jwtRequests.mu.Unlock()
	// An abandoned operation cannot publish over a newer request for this key.
	if m.jwtRequests.active[key] != request {
		return
	}
	if err == nil {
		err = m.jwtCache.SetJWTSVIDForRequest(key, request.registration, svid)
	}
	if err != nil {
		cached, ok := m.jwtCache.GetJWTSVIDForRequest(key)
		if ok && !rotationutil.JWTSVIDExpired(cached, m.clk.Now()) {
			m.c.Log.WithError(err).WithField(telemetry.RegistrationID, entryID).
				Warn("Unable to renew JWT; returning cached copy")
			svid, err = cached, nil
		} else {
			svid = nil
		}
	}
	request.svid, request.err = copyJWTSVID(svid), err
	delete(m.jwtRequests.active, key)
	close(request.done)
}

func (m *manager) updateJWTRegistrations(updates ...*cache.UpdateEntries) {
	authorized := make(map[cache.JWTRegistration]struct{})
	for _, update := range updates {
		for _, entry := range update.RegistrationEntries {
			authorized[cache.RegistrationForJWT(entry)] = struct{}{}
		}
	}
	m.jwtRequests.mu.Lock()
	defer m.jwtRequests.mu.Unlock()
	m.jwtRequests.authorized = authorized
	m.jwtCache.RetainJWTRegistrations(authorized)
	for key, request := range m.jwtRequests.active {
		if _, ok := authorized[request.registration]; ok {
			continue
		}
		request.err = status.Error(codes.PermissionDenied, "registration is no longer authorized")
		delete(m.jwtRequests.active, key)
		request.cancel()
		close(request.done)
	}
}

func copyJWTSVID(svid *client.JWTSVID) *client.JWTSVID {
	if svid == nil {
		return nil
	}
	svidCopy := *svid
	return &svidCopy
}
