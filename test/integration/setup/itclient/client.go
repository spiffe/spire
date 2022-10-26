package itclient

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	agent "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundle "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	debug "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	entry "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svid "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	tdFlag               = flag.String("trustDomain", "domain.test", "server trust domain")
	socketPathFlag       = flag.String("socketPath", "unix:///tmp/spire-agent/public/api.sock", "agent socket path")
	serverAddrFlag       = flag.String("serverAddr", "spire-server:8081", "server addr")
	serverSocketPathFlag = flag.String("serverSocketPath", "unix:///tmp/spire-server/private/api.sock", "server socket path")
	expectErrorsFlag     = flag.Bool("expectErrors", false, "client is used to validate permission errors")
)

type Client struct {
	ExpectErrors bool
	Td           spiffeid.TrustDomain

	connection *grpc.ClientConn
	source     *workloadapi.X509Source
}

func New(ctx context.Context) *Client {
	flag.Parse()

	td := spiffeid.RequireTrustDomainFromString(*tdFlag)

	// Create X509Source
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(*socketPathFlag), workloadapi.WithLogger(&logger{})))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}

	// Create connection
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	conn, err := grpc.DialContext(ctx, *serverAddrFlag, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		source.Close()
		log.Fatalf("Error creating dial: %v", err)
	}

	return &Client{
		Td:           td,
		ExpectErrors: *expectErrorsFlag,
		connection:   conn,
		source:       source,
	}
}

func NewInsecure(ctx context.Context) *Client {
	flag.Parse()
	tlsConfig := tls.Config{
		InsecureSkipVerify: true, // nolint: gosec // this is intentional for the integration test
	}
	conn, err := grpc.DialContext(ctx, *serverAddrFlag, grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig)))
	if err != nil {
		log.Fatalf("Error creating dial: %v", err)
	}

	return &Client{
		ExpectErrors: *expectErrorsFlag,
		connection:   conn,
	}
}

func NewWithCert(ctx context.Context, cert *x509.Certificate, key crypto.Signer) *Client {
	flag.Parse()

	tlsConfig := tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key,
			}, nil
		},
		InsecureSkipVerify: true, // nolint: gosec // this is intentional for the integration test
	}
	conn, err := grpc.DialContext(ctx, *serverAddrFlag, grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig)))
	if err != nil {
		log.Fatalf("Error creating dial: %v", err)
	}

	return &Client{
		ExpectErrors: *expectErrorsFlag,
		connection:   conn,
	}
}

func (c *Client) Release() {
	if c.connection != nil {
		c.connection.Close()
	}
	if c.source != nil {
		c.source.Close()
	}
}

func (c *Client) BundleClient() bundle.BundleClient {
	return bundle.NewBundleClient(c.connection)
}

func (c *Client) EntryClient() entry.EntryClient {
	return entry.NewEntryClient(c.connection)
}

func (c *Client) SVIDClient() svid.SVIDClient {
	return svid.NewSVIDClient(c.connection)
}

func (c *Client) AgentClient() agent.AgentClient {
	return agent.NewAgentClient(c.connection)
}

func (c *Client) DebugClient() debug.DebugClient {
	return debug.NewDebugClient(c.connection)
}

func (c *Client) TrustDomainClient() trustdomain.TrustDomainClient {
	return trustdomain.NewTrustDomainClient(c.connection)
}

// Open a client ON THE SPIRE-SERVER container
// Used for creating join tokens
type LocalServerClient struct {
	connection *grpc.ClientConn
}

func (c *LocalServerClient) AgentClient() agent.AgentClient {
	return agent.NewAgentClient(c.connection)
}

func (c *LocalServerClient) Release() {
	c.connection.Close()
}

func NewLocalServerClient(ctx context.Context) *LocalServerClient {
	flag.Parse()
	conn, err := grpc.DialContext(ctx, *serverSocketPathFlag, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Error creating dial: %v", err)
	}

	return &LocalServerClient{
		connection: conn,
	}
}

type logger struct{}

func (l *logger) Debugf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *logger) Infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *logger) Warnf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *logger) Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
