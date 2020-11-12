package endpoints

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/bundle/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	node_pb "github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// Number of entries that can be cached
	entriesCacheSize    = 500_000
	cacheReloadInterval = 5 * time.Second
)

func Middleware(log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, rlConf RateLimitConfig) middleware.Middleware {
	return middleware.Chain(
		middleware.WithLogger(log),
		middleware.WithMetrics(metrics),
		middleware.WithAuthorization(Authorization(log, ds, clk)),
		middleware.WithRateLimits(RateLimits(rlConf)),
	)
}

func Authorization(log logrus.FieldLogger, ds datastore.DataStore, clk clock.Clock) map[string]middleware.Authorizer {
	agentAuthorizer := AgentAuthorizer(log, ds, clk)
	entryFetcher := EntryFetcher(ds)

	any := middleware.AuthorizeAny()
	local := middleware.AuthorizeLocal()
	agent := middleware.AuthorizeAgent(agentAuthorizer)
	downstream := middleware.AuthorizeDownstream(entryFetcher)
	admin := middleware.AuthorizeAdmin(entryFetcher)

	localOrAdmin := middleware.AuthorizeAnyOf(local, admin)
	localOrAdminOrAgent := middleware.AuthorizeAnyOf(local, admin, agent)

	return map[string]middleware.Authorizer{
		"/spire.api.server.svid.v1.SVID/MintX509SVID":                   localOrAdmin,
		"/spire.api.server.svid.v1.SVID/MintJWTSVID":                    localOrAdmin,
		"/spire.api.server.svid.v1.SVID/BatchNewX509SVID":               agent,
		"/spire.api.server.svid.v1.SVID/NewJWTSVID":                     agent,
		"/spire.api.server.svid.v1.SVID/NewDownstreamX509CA":            downstream,
		"/spire.api.server.bundle.v1.Bundle/GetBundle":                  any,
		"/spire.api.server.bundle.v1.Bundle/AppendBundle":               localOrAdmin,
		"/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority":        downstream,
		"/spire.api.server.bundle.v1.Bundle/ListFederatedBundles":       localOrAdmin,
		"/spire.api.server.bundle.v1.Bundle/GetFederatedBundle":         localOrAdminOrAgent,
		"/spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle": localOrAdmin,
		"/spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle": localOrAdmin,
		"/spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle":    localOrAdmin,
		"/spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle": localOrAdmin,
		"/spire.api.server.debug.v1.Debug/GetInfo":                      local,
		"/spire.api.server.entry.v1.Entry/ListEntries":                  localOrAdmin,
		"/spire.api.server.entry.v1.Entry/GetEntry":                     localOrAdmin,
		"/spire.api.server.entry.v1.Entry/BatchCreateEntry":             localOrAdmin,
		"/spire.api.server.entry.v1.Entry/BatchUpdateEntry":             localOrAdmin,
		"/spire.api.server.entry.v1.Entry/BatchDeleteEntry":             localOrAdmin,
		"/spire.api.server.entry.v1.Entry/GetAuthorizedEntries":         agent,
		"/spire.api.server.agent.v1.Agent/ListAgents":                   localOrAdmin,
		"/spire.api.server.agent.v1.Agent/GetAgent":                     localOrAdmin,
		"/spire.api.server.agent.v1.Agent/DeleteAgent":                  localOrAdmin,
		"/spire.api.server.agent.v1.Agent/BanAgent":                     localOrAdmin,
		"/spire.api.server.agent.v1.Agent/AttestAgent":                  any,
		"/spire.api.server.agent.v1.Agent/RenewAgent":                   agent,
		"/spire.api.server.agent.v1.Agent/CreateJoinToken":              localOrAdmin,
	}
}

func EntryFetcher(ds datastore.DataStore) middleware.EntryFetcher {
	return middleware.EntryFetcherFunc(func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
		resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			BySpiffeId: &wrappers.StringValue{
				Value: id.String(),
			},
		})
		if err != nil {
			return nil, err
		}
		return api.RegistrationEntriesToProto(resp.Entries)
	})
}

func AuthorizedEntryFetcher(ds datastore.DataStore) api.AuthorizedEntryFetcher {
	return api.AuthorizedEntryFetcherFunc(func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
		entries, err := regentryutil.FetchRegistrationEntries(ctx, ds, agentID.String())
		if err != nil {
			return nil, err
		}
		return api.RegistrationEntriesToProto(entries)
	})
}

func AuthorizedEntryFetcherWithCache(ds datastore.DataStore) (api.AuthorizedEntryFetcher, error) {
	cache, err := entrycache.NewFetchX509SVIDCache(entriesCacheSize)
	if err != nil {
		return nil, fmt.Errorf("could not create cache: %v", err)
	}
	return api.AuthorizedEntryFetcherFunc(func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
		entries, err := regentryutil.FetchRegistrationEntriesWithCache(ctx, ds, cache, agentID.String())
		if err != nil {
			return nil, err
		}
		return api.RegistrationEntriesToProto(entries)
	}), nil
}

func AuthorizedEntryFetcherWithFullCache(log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore) api.AuthorizedEntryFetcher {
	return authorizedEntryFetcherWithFullCache(log, metrics, ds, time.Now)
}

func authorizedEntryFetcherWithFullCache(log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, nowFn func() time.Time) api.AuthorizedEntryFetcher {
	var mu sync.RWMutex
	var loaded time.Time
	var cache entrycache.Cache

	rebuildCache := func(ctx context.Context) (_ entrycache.Cache, err error) {
		call := telemetry.StartCall(metrics, "entry", "cache", "reload")
		defer call.Done(&err)
		return entrycache.BuildFromDataStore(ctx, ds)
	}

	return api.AuthorizedEntryFetcherFunc(func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
		mu.RLock()
		if !loaded.IsZero() && nowFn().Sub(loaded) < cacheReloadInterval {
			mu.RUnlock()
			return cache.GetAuthorizedEntries(agentID), nil
		}
		mu.RUnlock()

		mu.Lock()
		defer mu.Unlock()
		start := nowFn()
		if loaded.IsZero() || start.Sub(loaded) >= cacheReloadInterval {
			newCache, err := rebuildCache(ctx)
			end := nowFn()
			rebuildLog := log.WithField(telemetry.ElapsedTime, end.Sub(start))
			if err != nil {
				rebuildLog.WithError(err).Error("Failed to reload entry cache")
				return nil, err
			}
			rebuildLog.Debug("Reloaded entry cache")
			cache = newCache
			loaded = end
		}
		return cache.GetAuthorizedEntries(agentID), nil
	})
}

func UpstreamPublisher(manager *ca.Manager) bundle.UpstreamPublisher {
	return bundle.UpstreamPublisherFunc(manager.PublishJWTKey)
}

func AgentAuthorizer(log logrus.FieldLogger, ds datastore.DataStore, clk clock.Clock) middleware.AgentAuthorizer {
	return middleware.AgentAuthorizerFunc(func(ctx context.Context, agentID spiffeid.ID, agentSVID *x509.Certificate) error {
		id := agentID.String()
		log := log.WithField(telemetry.AgentID, id)

		permissionDenied := func(reason types.PermissionDeniedDetails_Reason, format string, args ...interface{}) error {
			st := status.Newf(codes.PermissionDenied, format, args...)
			if detailed, err := st.WithDetails(&types.PermissionDeniedDetails{
				Reason: reason,
			}); err == nil {
				st = detailed
			}
			return st.Err()
		}

		if clk.Now().After(agentSVID.NotAfter) {
			log.Error("Agent SVID is expired")
			return permissionDenied(types.PermissionDeniedDetails_AGENT_EXPIRED, "agent %q SVID is expired", id)
		}

		resp, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
			SpiffeId: id,
		})
		switch {
		case err != nil:
			log.WithError(err).Error("Unable to look up agent information")
			return status.Errorf(codes.Internal, "unable to look up agent information: %v", err)
		case resp.Node == nil:
			log.Error("Agent is not attested")
			return permissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ATTESTED, "agent %q is not attested", id)
		case resp.Node.CertSerialNumber == "":
			log.Error("Agent is banned")
			return permissionDenied(types.PermissionDeniedDetails_AGENT_BANNED, "agent %q is banned", id)
		case resp.Node.CertSerialNumber == agentSVID.SerialNumber.String():
			// AgentSVID matches the current serial number, access granted
			return nil
		case resp.Node.NewCertSerialNumber == agentSVID.SerialNumber.String():
			// AgentSVID matches the new serial number, access granted
			// Also update the attested node agent serial number from 'new' to 'current'
			_, err := ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
				SpiffeId:         resp.Node.SpiffeId,
				CertNotAfter:     resp.Node.NewCertNotAfter,
				CertSerialNumber: resp.Node.NewCertSerialNumber,
			})
			if err != nil {
				log.WithFields(logrus.Fields{
					telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
					telemetry.SerialNumber:     resp.Node.CertSerialNumber,
					telemetry.NewSerialNumber:  resp.Node.NewCertSerialNumber,
				}).WithError(err).Warningf("Unable to activate the new agent SVID")
				return status.Errorf(codes.Internal, "unable to activate the new agent SVID: %v", err)
			}
			return nil
		default:
			log.WithFields(logrus.Fields{
				telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
				telemetry.SerialNumber:     resp.Node.CertSerialNumber,
			}).Error("Agent SVID is not active")
			return permissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ACTIVE, "agent %q expected to have serial number %q; has %q", id, resp.Node.CertSerialNumber, agentSVID.SerialNumber.String())
		}
	})
}

func RateLimits(config RateLimitConfig) map[string]api.RateLimiter {
	noLimit := middleware.NoLimit()
	attestLimit := middleware.DisabledLimit()
	if config.Attestation {
		attestLimit = middleware.PerIPLimit(node_pb.AttestLimit)
	}
	csrLimit := middleware.PerIPLimit(node_pb.CSRLimit)
	jsrLimit := middleware.PerIPLimit(node_pb.JSRLimit)
	pushJWTKeyLimit := middleware.PerIPLimit(node_pb.PushJWTKeyLimit)

	return map[string]api.RateLimiter{
		"/spire.api.server.svid.v1.SVID/MintX509SVID":                   noLimit,
		"/spire.api.server.svid.v1.SVID/MintJWTSVID":                    noLimit,
		"/spire.api.server.svid.v1.SVID/BatchNewX509SVID":               csrLimit,
		"/spire.api.server.svid.v1.SVID/NewJWTSVID":                     jsrLimit,
		"/spire.api.server.svid.v1.SVID/NewDownstreamX509CA":            csrLimit,
		"/spire.api.server.bundle.v1.Bundle/GetBundle":                  noLimit,
		"/spire.api.server.bundle.v1.Bundle/AppendBundle":               noLimit,
		"/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority":        pushJWTKeyLimit,
		"/spire.api.server.bundle.v1.Bundle/ListFederatedBundles":       noLimit,
		"/spire.api.server.bundle.v1.Bundle/GetFederatedBundle":         noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle": noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle": noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle":    noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle": noLimit,
		"/spire.api.server.debug.v1.Debug/GetInfo":                      noLimit,
		"/spire.api.server.entry.v1.Entry/ListEntries":                  noLimit,
		"/spire.api.server.entry.v1.Entry/GetEntry":                     noLimit,
		"/spire.api.server.entry.v1.Entry/BatchCreateEntry":             noLimit,
		"/spire.api.server.entry.v1.Entry/BatchUpdateEntry":             noLimit,
		"/spire.api.server.entry.v1.Entry/BatchDeleteEntry":             noLimit,
		"/spire.api.server.entry.v1.Entry/GetAuthorizedEntries":         noLimit,
		"/spire.api.server.agent.v1.Agent/ListAgents":                   noLimit,
		"/spire.api.server.agent.v1.Agent/GetAgent":                     noLimit,
		"/spire.api.server.agent.v1.Agent/DeleteAgent":                  noLimit,
		"/spire.api.server.agent.v1.Agent/BanAgent":                     noLimit,
		"/spire.api.server.agent.v1.Agent/AttestAgent":                  attestLimit,
		"/spire.api.server.agent.v1.Agent/RenewAgent":                   csrLimit,
		"/spire.api.server.agent.v1.Agent/CreateJoinToken":              noLimit,
	}
}

func unaryInterceptorMux(oldInterceptor, newInterceptor grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		if !isOldAPI(info.FullMethod) {
			return newInterceptor(ctx, req, info, handler)
		}
		return oldInterceptor(ctx, req, info, handler)
	}
}

func streamInterceptorMux(oldInterceptor, newInterceptor grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !isOldAPI(info.FullMethod) {
			return newInterceptor(srv, ss, info, handler)
		}
		return oldInterceptor(srv, ss, info, handler)
	}
}

func isOldAPI(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, "/spire.api.node.") ||
		strings.HasPrefix(fullMethod, "/spire.api.registration.")
}
