package itclient

import (
	"context"
	"flag"
	"log"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	tdFlag           = flag.String("trustDomain", "domain.test", "server trust domain")
	socketPathFlag   = flag.String("socketPath", "unix:///tmp/agent.sock", "agent socket path")
	serverAddrFlag   = flag.String("serverAddr", "spire-server:8081", "server addr")
	expectErrorsFlag = flag.Bool("expectErrors", false, "client is used to validate permission errors")
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
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(*socketPathFlag)))
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

		connection: conn,
		source:     source,
	}
}

func (c *Client) Release() {
	c.connection.Close()
	c.source.Close()
}

func (c *Client) AgentClient() agent.AgentClient {
	return agent.NewAgentClient(c.connection)
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
