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
	// BindAddrs are the addresses the endpoint listens on. Each may be a
	// `*net.UnixAddr` or a `*net.TCPAddr`; the same gRPC server (and same
	// mTLS configuration) is fanned out across all of them.
	BindAddrs []net.Addr

	Manager manager.Manager

	Log logrus.FieldLogger

	Metrics telemetry.Metrics

	Attestor attestor.Attestor

	TrustDomain spiffeid.TrustDomain

	// Brokers enumerates the brokers authorized to talk to this endpoint.
	// mTLS at the listener gates the set; brokers absent from it are
	// rejected at the TLS layer.
	Brokers []Broker

	SVIDSource   x509svid.Source
	BundleSource x509bundle.Source
}

// Broker identifies a broker authorized to talk to the SPIFFE Broker API
// endpoint, and carries any per-broker configuration. Currently only ID is
// populated; the struct exists so per-broker fields can be added without
// breaking the Config API.
type Broker struct {
	// ID is the SPIFFE ID of the broker. MUST belong to the agent's trust
	// domain.
	ID string
}

type Endpoints struct {
	c *Config
}

func New(c *Config) (*Endpoints, error) {
	switch {
	case len(c.BindAddrs) == 0:
		return nil, fmt.Errorf("at least one BindAddr is required")
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
	if len(e.c.Brokers) == 0 {
		return fmt.Errorf("at least one broker is required")
	}

	brokerIDs, err := brokerIDsAsSPIFFEIDs(e.c.Brokers, e.c.TrustDomain)
	if err != nil {
		return fmt.Errorf("failed to parse broker IDs: %w", err)
	}

	// In comparison to the admin endpoints, this API is secured by mutual TLS using X.509 SVIDs.
	// Clients of this API are expected to use the Workload API to obtain their SVIDs first.
	// This is to accommodate environments where this API is served over network.
	tlsConfig := tlsconfig.MTLSServerConfig(e.c.SVIDSource, e.c.BundleSource, tlsconfig.AuthorizeOneOf(brokerIDs...))
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	e.registerBrokerAPI(server)
	reflection.Register(server)

	listeners := make([]net.Listener, 0, len(e.c.BindAddrs))
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for _, addr := range e.c.BindAddrs {
		var l net.Listener
		switch addr.Network() {
		case "unix":
			l, err = createUDSListener(addr)
		case "tcp":
			// TCP is permitted because the SPIFFE Broker API is secured by
			// mutual TLS using X.509-SVIDs, so the listener is safe to
			// expose over the network.
			l, err = net.Listen("tcp", addr.String())
		default:
			err = fmt.Errorf("unsupported network type %q for broker endpoint", addr.Network())
		}
		if err != nil {
			return fmt.Errorf("failed to listen on broker address %q: %w", addr.String(), err)
		}
		listeners = append(listeners, l)
		e.c.Log.WithFields(logrus.Fields{
			telemetry.Network: l.Addr().Network(),
			telemetry.Address: l.Addr().String(),
		}).Info("Starting SPIFFE Broker Endpoint")
	}

	// Fan one gRPC server out across every listener. The first to error
	// (or context cancellation) tears them all down via server.Stop, which
	// causes every blocked Serve to return.
	errChan := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l net.Listener) { errChan <- server.Serve(l) }(l)
	}

	select {
	case err = <-errChan:
		e.c.Log.WithError(err).Error("SPIFFE Broker Endpoint stopped prematurely")
		server.Stop()
		// Drain the rest so goroutines exit cleanly.
		for i := 1; i < len(listeners); i++ {
			<-errChan
		}
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping SPIFFE Broker Endpoint")
		server.Stop()
		for range listeners {
			<-errChan
		}
		e.c.Log.Info("SPIFFE Broker Endpoint has stopped")
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

// brokerIDsAsSPIFFEIDs validates and parses each broker's ID into a
// spiffeid.ID, enforcing trust-domain membership. The Delegated Identity
// API allows delegates from foreign trust domains, but the SPIFFE Broker
// Endpoint may be offered over the network, so a stricter rule applies
// here: every authorized broker MUST be a member of the agent's trust
// domain.
func brokerIDsAsSPIFFEIDs(brokers []Broker, trustDomain spiffeid.TrustDomain) ([]spiffeid.ID, error) {
	ids := make([]spiffeid.ID, 0, len(brokers))
	for _, b := range brokers {
		id, err := spiffeid.FromString(b.ID)
		if err != nil {
			return nil, err
		}
		if id.TrustDomain() != trustDomain {
			return nil, fmt.Errorf("broker %q is not in trust domain %q", b.ID, trustDomain.Name())
		}
		ids = append(ids, id)
	}
	return ids, nil
}
