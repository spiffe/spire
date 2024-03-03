package endpoints

import (
	"context"
	"crypto/x509"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/errorutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/bundle/v1"
	"github.com/spiffe/spire/pkg/server/api/limits"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Middleware(log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, rlConf RateLimitConfig, policyEngine *authpolicy.Engine, auditLogEnabled bool, adminIDs []spiffeid.ID) middleware.Middleware {
	chain := []middleware.Middleware{
		middleware.WithLogger(log),
		middleware.WithMetrics(metrics),
		middleware.WithAuthorization(policyEngine, EntryFetcher(ds), AgentAuthorizer(ds, clk), adminIDs),
		middleware.WithRateLimits(RateLimits(rlConf), metrics),
	}

	if auditLogEnabled {
		// Add audit log with local tracking enabled
		chain = append(chain, middleware.WithAuditLog(true))
	}

	return middleware.Chain(
		chain...,
	)
}

func EntryFetcher(ds datastore.DataStore) middleware.EntryFetcher {
	return middleware.EntryFetcherFunc(func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
		resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			BySpiffeID: id.String(),
		})
		if err != nil {
			return nil, err
		}
		return api.RegistrationEntriesToProto(resp.Entries)
	})
}

func UpstreamPublisher(jwtKeyPublisher manager.JwtKeyPublisher) bundle.UpstreamPublisher {
	return bundle.UpstreamPublisherFunc(jwtKeyPublisher.PublishJWTKey)
}

func AgentAuthorizer(ds datastore.DataStore, clk clock.Clock) middleware.AgentAuthorizer {
	return middleware.AgentAuthorizerFunc(func(ctx context.Context, agentID spiffeid.ID, agentSVID *x509.Certificate) error {
		id := agentID.String()
		log := rpccontext.Logger(ctx)

		if clk.Now().After(agentSVID.NotAfter) {
			log.Error("Agent SVID is expired")
			return errorutil.PermissionDenied(types.PermissionDeniedDetails_AGENT_EXPIRED, "agent %q SVID is expired", id)
		}

		attestedNode, err := ds.FetchAttestedNode(ctx, id)
		switch {
		case err != nil:
			log.WithError(err).Error("Unable to look up agent information")
			return status.Errorf(codes.Internal, "unable to look up agent information: %v", err)
		case attestedNode == nil:
			log.Error("Agent is not attested")
			return errorutil.PermissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ATTESTED, "agent %q is not attested", id)
		case attestedNode.CertSerialNumber == "":
			log.Error("Agent is banned")
			return errorutil.PermissionDenied(types.PermissionDeniedDetails_AGENT_BANNED, "agent %q is banned", id)
		case attestedNode.CertSerialNumber == agentSVID.SerialNumber.String():
			// AgentSVID matches the current serial number, access granted
			return nil
		case attestedNode.NewCertSerialNumber == agentSVID.SerialNumber.String():
			// AgentSVID matches the new serial number, access granted
			// Also update the attested node agent serial number from 'new' to 'current'
			_, err := ds.UpdateAttestedNode(ctx, &common.AttestedNode{
				SpiffeId:         attestedNode.SpiffeId,
				CertNotAfter:     attestedNode.NewCertNotAfter,
				CertSerialNumber: attestedNode.NewCertSerialNumber,
				CanReattest:      attestedNode.CanReattest,
			}, nil)
			if err != nil {
				log.WithFields(logrus.Fields{
					telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
					telemetry.SerialNumber:     attestedNode.CertSerialNumber,
					telemetry.NewSerialNumber:  attestedNode.NewCertSerialNumber,
				}).WithError(err).Warningf("Unable to activate the new agent SVID")
				return status.Errorf(codes.Internal, "unable to activate the new agent SVID: %v", err)
			}
			return nil
		default:
			log.WithFields(logrus.Fields{
				telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
				telemetry.SerialNumber:     attestedNode.CertSerialNumber,
			}).Error("Agent SVID is not active")
			return errorutil.PermissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ACTIVE, "agent %q expected to have serial number %q; has %q", id, attestedNode.CertSerialNumber, agentSVID.SerialNumber.String())
		}
	})
}

func RateLimits(config RateLimitConfig) map[string]api.RateLimiter {
	noLimit := middleware.NoLimit()
	attestLimit := middleware.DisabledLimit()
	if config.Attestation {
		attestLimit = middleware.PerIPLimit(limits.AttestLimitPerIP)
	}

	csrLimit := middleware.DisabledLimit()
	if config.Signing {
		csrLimit = middleware.PerIPLimit(limits.SignLimitPerIP)
	}

	jsrLimit := middleware.DisabledLimit()
	if config.Signing {
		jsrLimit = middleware.PerIPLimit(limits.SignLimitPerIP)
	}

	pushJWTKeyLimit := middleware.PerIPLimit(limits.PushJWTKeyLimitPerIP)

	return map[string]api.RateLimiter{
		"/spire.api.server.svid.v1.SVID/MintX509SVID":                                    noLimit,
		"/spire.api.server.svid.v1.SVID/MintJWTSVID":                                     noLimit,
		"/spire.api.server.svid.v1.SVID/BatchNewX509SVID":                                csrLimit,
		"/spire.api.server.svid.v1.SVID/NewJWTSVID":                                      jsrLimit,
		"/spire.api.server.svid.v1.SVID/NewDownstreamX509CA":                             csrLimit,
		"/spire.api.server.bundle.v1.Bundle/GetBundle":                                   noLimit,
		"/spire.api.server.bundle.v1.Bundle/AppendBundle":                                noLimit,
		"/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority":                         pushJWTKeyLimit,
		"/spire.api.server.bundle.v1.Bundle/CountBundles":                                noLimit,
		"/spire.api.server.bundle.v1.Bundle/ListFederatedBundles":                        noLimit,
		"/spire.api.server.bundle.v1.Bundle/GetFederatedBundle":                          noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle":                  noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle":                  noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle":                     noLimit,
		"/spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle":                  noLimit,
		"/spire.api.server.debug.v1.Debug/GetInfo":                                       noLimit,
		"/spire.api.server.entry.v1.Entry/CountEntries":                                  noLimit,
		"/spire.api.server.entry.v1.Entry/ListEntries":                                   noLimit,
		"/spire.api.server.entry.v1.Entry/GetEntry":                                      noLimit,
		"/spire.api.server.entry.v1.Entry/BatchCreateEntry":                              noLimit,
		"/spire.api.server.entry.v1.Entry/BatchUpdateEntry":                              noLimit,
		"/spire.api.server.entry.v1.Entry/BatchDeleteEntry":                              noLimit,
		"/spire.api.server.entry.v1.Entry/GetAuthorizedEntries":                          noLimit,
		"/spire.api.server.entry.v1.Entry/SyncAuthorizedEntries":                         noLimit,
		"/spire.api.server.logger.v1.Logger/GetLogger":                                   noLimit,
		"/spire.api.server.logger.v1.Logger/SetLogLevel":                                 noLimit,
		"/spire.api.server.logger.v1.Logger/ResetLogLevel":                               noLimit,
		"/spire.api.server.agent.v1.Agent/CountAgents":                                   noLimit,
		"/spire.api.server.agent.v1.Agent/ListAgents":                                    noLimit,
		"/spire.api.server.agent.v1.Agent/GetAgent":                                      noLimit,
		"/spire.api.server.agent.v1.Agent/DeleteAgent":                                   noLimit,
		"/spire.api.server.agent.v1.Agent/BanAgent":                                      noLimit,
		"/spire.api.server.agent.v1.Agent/AttestAgent":                                   attestLimit,
		"/spire.api.server.agent.v1.Agent/RenewAgent":                                    csrLimit,
		"/spire.api.server.agent.v1.Agent/CreateJoinToken":                               noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/ListFederationRelationships":       noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/GetFederationRelationship":         noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/BatchCreateFederationRelationship": noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/BatchUpdateFederationRelationship": noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/BatchDeleteFederationRelationship": noLimit,
		"/spire.api.server.trustdomain.v1.TrustDomain/RefreshBundle":                     noLimit,
		"/grpc.health.v1.Health/Check":                                                   noLimit,
		"/grpc.health.v1.Health/Watch":                                                   noLimit,
	}
}
