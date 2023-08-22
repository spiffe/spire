package endpoints

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	agentv1 "github.com/spiffe/spire/pkg/server/api/agent/v1"
	bundlev1 "github.com/spiffe/spire/pkg/server/api/bundle/v1"
	debugv1 "github.com/spiffe/spire/pkg/server/api/debug/v1"
	entryv1 "github.com/spiffe/spire/pkg/server/api/entry/v1"
	healthv1 "github.com/spiffe/spire/pkg/server/api/health/v1"
	svidv1 "github.com/spiffe/spire/pkg/server/api/svid/v1"
	trustdomainv1 "github.com/spiffe/spire/pkg/server/api/trustdomain/v1"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	bundle_client "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/svid"
	"golang.org/x/net/context"
)

// Config is a configuration for endpoints
type Config struct {
	// TPCAddr is the address to bind the TCP listener to.
	TCPAddr *net.TCPAddr

	// LocalAddr is the local address to bind the listener to.
	LocalAddr net.Addr

	// The svid rotator used to obtain the latest server credentials
	SVIDObserver svid.Observer

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain spiffeid.TrustDomain

	// Plugin catalog
	Catalog catalog.Catalog

	// Server CA for signing SVIDs
	ServerCA ca.ServerCA

	// Bundle endpoint configuration
	BundleEndpoint bundle.EndpointConfig

	// JWTKey publisher
	JWTKeyPublisher manager.JwtKeyPublisher

	// Makes policy decisions
	AuthPolicyEngine *authpolicy.Engine

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	// RateLimit holds rate limiting configurations.
	RateLimit RateLimitConfig

	Uptime func() time.Duration

	Clock clock.Clock

	// CacheReloadInterval controls how often the in-memory entry cache reloads
	CacheReloadInterval time.Duration

	AuditLogEnabled bool

	// AdminIDs are a list of fixed IDs that when presented by a caller in an
	// X509-SVID, are granted admin rights.
	AdminIDs []spiffeid.ID

	BundleManager *bundle_client.Manager
}

func (c *Config) maybeMakeBundleEndpointServer() Server {
	if c.BundleEndpoint.Address == nil {
		return nil
	}
	c.Log.WithField("addr", c.BundleEndpoint.Address).Info("Serving bundle endpoint")

	var serverAuth bundle.ServerAuth
	if c.BundleEndpoint.ACME != nil {
		serverAuth = bundle.ACMEAuth(c.Log.WithField(telemetry.SubsystemName, "bundle_acme"), c.Catalog.GetKeyManager(), *c.BundleEndpoint.ACME)
	} else {
		serverAuth = bundle.SPIFFEAuth(func() ([]*x509.Certificate, crypto.PrivateKey, error) {
			state := c.SVIDObserver.State()
			return state.SVID, state.Key, nil
		})
	}

	ds := c.Catalog.GetDataStore()
	return bundle.NewServer(bundle.ServerConfig{
		Log:     c.Log.WithField(telemetry.SubsystemName, "bundle_endpoint"),
		Address: c.BundleEndpoint.Address.String(),
		Getter: bundle.GetterFunc(func(ctx context.Context) (*spiffebundle.Bundle, error) {
			commonBundle, err := ds.FetchBundle(dscache.WithCache(ctx), c.TrustDomain.IDString())
			if err != nil {
				return nil, err
			}
			if commonBundle == nil {
				return nil, errors.New("trust domain bundle not found")
			}
			return bundleutil.SPIFFEBundleFromProto(commonBundle)
		}),
		RefreshHint: c.BundleEndpoint.RefreshHint,
		ServerAuth:  serverAuth,
	})
}

func (c *Config) makeAPIServers(entryFetcher api.AuthorizedEntryFetcher) APIServers {
	ds := c.Catalog.GetDataStore()
	upstreamPublisher := UpstreamPublisher(c.JWTKeyPublisher)

	return APIServers{
		AgentServer: agentv1.New(agentv1.Config{
			DataStore:   ds,
			ServerCA:    c.ServerCA,
			TrustDomain: c.TrustDomain,
			Catalog:     c.Catalog,
			Clock:       c.Clock,
		}),
		BundleServer: bundlev1.New(bundlev1.Config{
			TrustDomain:       c.TrustDomain,
			DataStore:         ds,
			UpstreamPublisher: upstreamPublisher,
		}),
		DebugServer: debugv1.New(debugv1.Config{
			TrustDomain:  c.TrustDomain,
			Clock:        c.Clock,
			DataStore:    ds,
			SVIDObserver: c.SVIDObserver,
			Uptime:       c.Uptime,
		}),
		EntryServer: entryv1.New(entryv1.Config{
			TrustDomain:  c.TrustDomain,
			DataStore:    ds,
			EntryFetcher: entryFetcher,
		}),
		HealthServer: healthv1.New(healthv1.Config{
			TrustDomain: c.TrustDomain,
			DataStore:   ds,
		}),
		SVIDServer: svidv1.New(svidv1.Config{
			TrustDomain:  c.TrustDomain,
			EntryFetcher: entryFetcher,
			ServerCA:     c.ServerCA,
			DataStore:    ds,
		}),
		TrustDomainServer: trustdomainv1.New(trustdomainv1.Config{
			TrustDomain:     c.TrustDomain,
			DataStore:       ds,
			BundleRefresher: c.BundleManager,
		}),
	}
}
