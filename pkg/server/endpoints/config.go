package endpoints

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentv1 "github.com/spiffe/spire/pkg/server/api/agent/v1"
	bundlev1 "github.com/spiffe/spire/pkg/server/api/bundle/v1"
	entryv1 "github.com/spiffe/spire/pkg/server/api/entry/v1"
	svidv1 "github.com/spiffe/spire/pkg/server/api/svid/v1"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	"golang.org/x/net/context"
)

// Config is a configuration for endpoints
type Config struct {
	// TPCAddr is the address to bind the TCP listener to.
	TCPAddr *net.TCPAddr

	// UDSAddr is the address to bind the UDS listener to.
	UDSAddr *net.UnixAddr

	// The svid rotator used to obtain the latest server credentials
	SVIDObserver svid.Observer

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain spiffeid.TrustDomain

	// Plugin catalog
	Catalog catalog.Catalog

	// Server CA for signing SVIDs
	ServerCA ca.ServerCA

	// Allow agentless spiffeIds when doing node attestation
	AllowAgentlessNodeAttestors bool

	// Bundle endpoint configuration
	BundleEndpoint bundle.EndpointConfig

	// EnableExperimentalAPI enables the experimental API
	EnableExperimentalAPI bool

	// CA Manager
	Manager *ca.Manager

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics
}

func (c *Config) makeRegistrationHandler() *registration.Handler {
	return &registration.Handler{
		Log:         c.Log.WithField(telemetry.SubsystemName, telemetry.RegistrationAPI),
		Metrics:     c.Metrics,
		Catalog:     c.Catalog,
		TrustDomain: *c.TrustDomain.ID().URL(),
		ServerCA:    c.ServerCA,
	}
}

func (c *Config) makeNodeHandler() (*node.Handler, error) {
	return node.NewHandler(node.HandlerConfig{
		Log:                         c.Log.WithField(telemetry.SubsystemName, telemetry.NodeAPI),
		Metrics:                     c.Metrics,
		Catalog:                     c.Catalog,
		TrustDomain:                 *c.TrustDomain.ID().URL(),
		ServerCA:                    c.ServerCA,
		Manager:                     c.Manager,
		AllowAgentlessNodeAttestors: c.AllowAgentlessNodeAttestors,
	})
}

func (c *Config) maybeMakeBundleServer() Server {
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
		Getter: bundle.GetterFunc(func(ctx context.Context) (*bundleutil.Bundle, error) {
			resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
				TrustDomainId: c.TrustDomain.IDString(),
			})
			if err != nil {
				return nil, err
			}
			if resp.Bundle == nil {
				return nil, errors.New("trust domain bundle not found")
			}
			return bundleutil.BundleFromProto(resp.Bundle)
		}),
		ServerAuth: serverAuth,
	})
}

func (c *Config) maybeMakeExperimentalServers() *ExperimentalServers {
	if !c.EnableExperimentalAPI {
		return nil
	}

	ds := c.Catalog.GetDataStore()
	authorizedEntryFetcher := AuthorizedEntryFetcher(ds)

	return &ExperimentalServers{
		AgentServer: agentv1.New(agentv1.Config{
			DataStore: ds,
		}),
		BundleServer: bundlev1.New(bundlev1.Config{
			TrustDomain: c.TrustDomain,
			DataStore:   ds,
		}),
		EntryServer: entryv1.New(entryv1.Config{
			DataStore:    ds,
			EntryFetcher: authorizedEntryFetcher,
		}),
		SVIDServer: svidv1.New(svidv1.Config{
			TrustDomain:  c.TrustDomain,
			EntryFetcher: authorizedEntryFetcher,
			ServerCA:     c.ServerCA,
		}),
	}
}
