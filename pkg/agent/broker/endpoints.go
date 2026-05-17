package broker

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	brokerapi "github.com/spiffe/spire/pkg/agent/broker/api"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/sync/errgroup"
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

	// Brokers enumerates the brokers authorized to talk to this endpoint.
	// mTLS at the listener gates the set; brokers absent from it are
	// rejected at the TLS layer.
	Brokers []Broker

	SVIDSource   x509svid.Source
	BundleSource x509bundle.Source

	// TLSPolicy controls the post-quantum-safe TLS policy applied to the
	// inbound mTLS listener.
	TLSPolicy tlspolicy.Policy
}

// Broker identifies a broker authorized to talk to the SPIFFE Broker API
// endpoint, and carries any per-broker configuration.
type Broker struct {
	// ID is the SPIFFE ID of the broker. Cross-trust-domain broker
	// identities are allowed.
	ID string

	// AllowedReferenceTypes restricts which WorkloadReference types this
	// broker is permitted to use. Each entry is the verbatim protobuf type
	// URL the workload attestor plugin matches against (e.g.
	// `type.googleapis.com/spiffe.reference.KubernetesObjectReference`).
	// Use `"*"` to allow any reference type this agent's workload attestor
	// stack understands. Must list at least one entry.
	AllowedReferenceTypes []string
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
		middleware.Chain(
			endpoints.Middleware(e.c.Log, e.c.Metrics),
			middleware.Preprocess(verifyBrokerSecurityHeader),
		),
	)

	// TODO(arndt): Delegated Identity API allows to be served without any authorized peer.
	// I think it's better to fail as it's a misconfiguration and having that socket up
	// without any authorized peer is just a potential security risk.
	if len(e.c.Brokers) == 0 {
		return fmt.Errorf("at least one broker is required")
	}

	brokerIDs, err := brokerIDsAsSPIFFEIDs(e.c.Brokers)
	if err != nil {
		return fmt.Errorf("failed to parse broker IDs: %w", err)
	}

	// In comparison to the admin endpoints, this API is secured by mutual TLS using X.509 SVIDs.
	// Clients of this API are expected to use the Workload API to obtain their SVIDs first.
	// This is to accommodate environments where this API is served over network.
	tlsConfig := tlsconfig.MTLSServerConfig(e.c.SVIDSource, e.c.BundleSource, tlsconfig.AuthorizeOneOf(brokerIDs...))
	// Disable session ticket resumption so the peer-authorization callback
	// runs on every connection — same rationale as the SPIRE server endpoint.
	tlsConfig.SessionTicketsDisabled = true
	if err := tlspolicy.ApplyPolicy(tlsConfig, e.c.TLSPolicy); err != nil {
		return fmt.Errorf("failed to apply TLS policy: %w", err)
	}
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

	// Fan one gRPC server out across every listener with an errgroup. The
	// first goroutine to error (or context cancellation) cancels the
	// errgroup's context, which the watcher goroutine uses to call
	// server.Stop(), causing every blocked Serve to return.
	g, gCtx := errgroup.WithContext(ctx)
	for _, l := range listeners {
		g.Go(func() error {
			if err := server.Serve(l); err != nil && err != grpc.ErrServerStopped {
				return err
			}
			return nil
		})
	}
	g.Go(func() error {
		<-gCtx.Done()
		e.c.Log.Info("Stopping SPIFFE Broker Endpoint")
		server.Stop()
		return nil
	})

	if err := g.Wait(); err != nil {
		e.c.Log.WithError(err).Error("SPIFFE Broker Endpoint stopped prematurely")
		return err
	}
	e.c.Log.Info("SPIFFE Broker Endpoint has stopped")
	return nil
}

func (e *Endpoints) registerBrokerAPI(server *grpc.Server) {
	service := brokerapi.New(brokerapi.Config{
		Manager:                       e.c.Manager,
		Attestor:                      e.c.Attestor,
		Metrics:                       e.c.Metrics,
		Log:                           e.c.Log.WithField(telemetry.SubsystemName, telemetry.BrokerAPI),
		AllowedReferenceTypesByCaller: buildAllowedReferenceTypeMap(e.c.Brokers),
	})

	brokerapi.RegisterService(server, service)
}

// buildAllowedReferenceTypeMap pre-computes the per-caller allowlist used
// by the api service to gate WorkloadReference type usage. Brokers whose
// allowed list contains "*" are absent from the map; the api service
// treats absence as "no restriction." Brokers whose ID fails to parse
// are skipped — the mTLS authorizer will already have rejected them at
// the listener level since the same parse runs in brokerIDsAsSPIFFEIDs.
func buildAllowedReferenceTypeMap(brokers []Broker) map[spiffeid.ID]map[string]struct{} {
	if len(brokers) == 0 {
		return nil
	}
	out := make(map[spiffeid.ID]map[string]struct{})
	for _, b := range brokers {
		if slices.Contains(b.AllowedReferenceTypes, "*") {
			continue
		}
		id, err := spiffeid.FromString(b.ID)
		if err != nil {
			continue
		}
		set := make(map[string]struct{}, len(b.AllowedReferenceTypes))
		for _, t := range b.AllowedReferenceTypes {
			set[t] = struct{}{}
		}
		out[id] = set
	}
	return out
}

// verifyBrokerSecurityHeader enforces the SPIFFE Broker Endpoint spec
// requirement that every request carries the `broker.spiffe.io: true` gRPC
// metadata header — an SSRF mitigation analogous to the Workload API's
// `workload.spiffe.io` header. Requests missing or mismatching it are
// rejected with InvalidArgument.
func verifyBrokerSecurityHeader(ctx context.Context, _ string, _ any) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md["broker.spiffe.io"]
	if len(values) != 1 || values[0] != "true" {
		return nil, status.Error(codes.InvalidArgument, "security header missing from request")
	}
	return ctx, nil
}

// brokerIDsAsSPIFFEIDs parses each broker's ID into a spiffeid.ID. Brokers
// from any trust domain are allowed; mTLS at the listener still pins
// authorization to the configured set of identities.
func brokerIDsAsSPIFFEIDs(brokers []Broker) ([]spiffeid.ID, error) {
	ids := make([]spiffeid.ID, 0, len(brokers))
	for _, b := range brokers {
		id, err := spiffeid.FromString(b.ID)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
