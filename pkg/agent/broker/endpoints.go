package broker

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	brokerapi "github.com/spiffe/spire/pkg/agent/broker/api"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type Config struct {
	BindAddr net.Addr

	Manager manager.Manager

	Log logrus.FieldLogger

	Metrics telemetry.Metrics

	Attestor attestor.Attestor

	TrustDomain spiffeid.TrustDomain

	AuthorizedDelegates []string

	SVIDSource   x509svid.Source
	BundleSource x509bundle.Source
}

type Endpoints struct {
	c *Config
}

func New(c *Config) (*Endpoints, error) {
	switch {
	case c.BindAddr == nil:
		return nil, fmt.Errorf("BindAddr is required")
	case c.Manager == nil:
		return nil, fmt.Errorf("Manager is required")
	case c.Log == nil:
		return nil, fmt.Errorf("Log is required")
	case c.Metrics == nil:
		return nil, fmt.Errorf("Metrics is required")
	case c.Attestor == nil:
		return nil, fmt.Errorf("Attestor is required")
	case c.TrustDomain == spiffeid.TrustDomain{}:
		return nil, fmt.Errorf("TrustDomain is required")
	case c.SVIDSource == nil:
		return nil, fmt.Errorf("SVIDSource is required")
	case c.BundleSource == nil:
		return nil, fmt.Errorf("BundleSource is required")
	}
	return &Endpoints{
		c: c,
	}, nil
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	unaryInterceptor, streamInterceptor := middleware.Interceptors(
		endpoints.Middleware(e.c.Log, e.c.Metrics),
	)

	// TODO(arndt): Delegated Identity API allows to be served without any authorized peer.
	// I think it's better to fail as it's a misconfiguration and having that socket up
	// without any authorized peer is just a potential security risk.
	if len(e.c.AuthorizedDelegates) == 0 {
		return fmt.Errorf("at least one authorized delegate is required")
	}

	authorizedDelegates, err := delegatesFromStrings(e.c.AuthorizedDelegates, e.c.TrustDomain)
	if err != nil {
		return fmt.Errorf("failed to parse authorized delegates: %w", err)
	}

	// In comparison to the admin endpoints, this API is secured by mutual TLS using X.509 SVIDs.
	// Clients of this API are expected to use the Workload API to obtain their SVIDs first.
	// This is to accommodate environments where this API is served over network.
	tlsConfig := tlsconfig.MTLSServerConfig(e.c.SVIDSource, e.c.BundleSource, tlsconfig.AuthorizeOneOf(authorizedDelegates...))
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	e.registerBrokerAPI(server)
	reflection.Register(server)

	var l net.Listener
	switch e.c.BindAddr.Network() {
	case "unix":
		l, err = createUDSListener(e.c.BindAddr)
		if err != nil {
			return err
		}
		defer l.Close()
	default:
		return fmt.Errorf("unsupported network type %q for broker endpoint", e.c.BindAddr.Network())
	}

	log := e.c.Log.WithFields(logrus.Fields{
		telemetry.Network: l.Addr().Network(),
		telemetry.Address: l.Addr().String()})
	log.Info("Starting SPIFFE Broker Endpoint")

	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		log.WithError(err).Error("SPIFFE Broker Endpoint stopped prematurely")
		return err
	case <-ctx.Done():
		log.Info("Stopping SPIFFE Broker Endpoint")
		server.Stop()
		<-errChan
		log.Info("SPIFFE Broker Endpoint has stopped")
		return nil
	}
}

func (e *Endpoints) registerBrokerAPI(server *grpc.Server) {
	service := brokerapi.New(brokerapi.Config{
		Manager:  e.c.Manager,
		Attestor: e.c.Attestor,
		Metrics:  e.c.Metrics,
		Log:      e.c.Log.WithField(telemetry.SubsystemName, telemetry.BrokerAPI),
	})

	brokerapi.RegisterService(server, service)
}

func delegatesFromStrings(delegates []string, trustDomain spiffeid.TrustDomain) ([]spiffeid.ID, error) {
	var ids []spiffeid.ID
	for _, d := range delegates {
		id, err := spiffeid.FromString(d)
		if err != nil {
			return nil, err
		}
		// TODO(arndt): This also differs from the admin API where it's possible to define delegates
		// from other trust domains. Here we enforce that delegates must be in the same trust domain
		// as the agent.
		// I suppose technically it's not possible on the admin API to encounter this, but considering that
		// the SPIFFE Broker Endpoint may be offered over the network in the future I think it's better to
		// enforce this here.
		if id.TrustDomain() != trustDomain {
			return nil, fmt.Errorf("delegate %q is not in trust domain %q", d, trustDomain.Name())
		}
		ids = append(ids, id)
	}
	return ids, nil
}
