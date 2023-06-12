package util

import (
	"context"
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	api_types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

const (
	DefaultSocketPath    = "/tmp/spire-server/private/api.sock"
	DefaultNamedPipeName = "\\spire-server\\private\\api"
	FormatPEM            = "pem"
	FormatSPIFFE         = "spiffe"
)

func Dial(addr net.Addr) (*grpc.ClientConn, error) {
	return grpc.Dial(addr.String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithReturnConnectionError())
}

type ServerClient interface {
	Release()
	NewAgentClient() agentv1.AgentClient
	NewBundleClient() bundlev1.BundleClient
	NewEntryClient() entryv1.EntryClient
	NewSVIDClient() svidv1.SVIDClient
	NewTrustDomainClient() trustdomainv1.TrustDomainClient
	NewHealthClient() grpc_health_v1.HealthClient
}

func NewServerClient(addr net.Addr) (ServerClient, error) {
	conn, err := Dial(addr)
	if err != nil {
		return nil, err
	}
	return &serverClient{conn: conn}, nil
}

type serverClient struct {
	conn *grpc.ClientConn
}

func (c *serverClient) Release() {
	c.conn.Close()
}

func (c *serverClient) NewAgentClient() agentv1.AgentClient {
	return agentv1.NewAgentClient(c.conn)
}

func (c *serverClient) NewBundleClient() bundlev1.BundleClient {
	return bundlev1.NewBundleClient(c.conn)
}

func (c *serverClient) NewEntryClient() entryv1.EntryClient {
	return entryv1.NewEntryClient(c.conn)
}

func (c *serverClient) NewSVIDClient() svidv1.SVIDClient {
	return svidv1.NewSVIDClient(c.conn)
}

func (c *serverClient) NewTrustDomainClient() trustdomainv1.TrustDomainClient {
	return trustdomainv1.NewTrustDomainClient(c.conn)
}

func (c *serverClient) NewHealthClient() grpc_health_v1.HealthClient {
	return grpc_health_v1.NewHealthClient(c.conn)
}

// Pluralizer concatenates `singular` to `msg` when `val` is one, and
// `plural` on all other occasions. It is meant to facilitate friendlier
// CLI output.
func Pluralizer(msg string, singular string, plural string, val int) string {
	result := msg
	if val == 1 {
		result += singular
	} else {
		result += plural
	}

	return result
}

// Command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type Command interface {
	Name() string
	Synopsis() string
	AppendFlags(*flag.FlagSet)
	Run(context.Context, *common_cli.Env, ServerClient) error
}

type Adapter struct {
	env *common_cli.Env
	cmd Command

	flags *flag.FlagSet

	adapterOS // OS specific
}

// AdaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func AdaptCommand(env *common_cli.Env, cmd Command) *Adapter {
	a := &Adapter{
		cmd: cmd,
		env: env,
	}

	f := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	f.SetOutput(env.Stderr)
	a.addOSFlags(f)
	a.cmd.AppendFlags(f)
	a.flags = f

	return a
}

func (a *Adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		return 1
	}

	addr, err := a.getAddr()
	if err != nil {
		fmt.Fprintln(a.env.Stderr, "Error: "+err.Error())
		return 1
	}

	client, err := NewServerClient(addr)
	if err != nil {
		fmt.Fprintln(a.env.Stderr, "Error: "+err.Error())
		return 1
	}
	defer client.Release()

	if err := a.cmd.Run(ctx, a.env, client); err != nil {
		fmt.Fprintln(a.env.Stderr, "Error: "+err.Error())
		return 1
	}

	return 0
}

func (a *Adapter) Help() string {
	return a.flags.Parse([]string{"-h"}).Error()
}

func (a *Adapter) Synopsis() string {
	return a.cmd.Synopsis()
}

// parseSelector parses a CLI string from type:value into a selector type.
// Everything to the right of the first ":" is considered a selector value.
func ParseSelector(str string) (*api_types.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &api_types.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}

func ParseBundle(bundleBytes []byte, format, id string) (*api_types.Bundle, error) {
	var bundle *api_types.Bundle
	switch format {
	case FormatPEM:
		rootCAs, err := pemutil.ParseCertificates(bundleBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse bundle data: %w", err)
		}

		bundle = bundleProtoFromX509Authorities(id, rootCAs)
	default:
		td, err := spiffeid.TrustDomainFromString(id)
		if err != nil {
			return nil, err
		}

		spiffeBundle, err := spiffebundle.Parse(td, bundleBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse to spiffe bundle: %w", err)
		}

		bundle, err = protoFromSpiffeBundle(spiffeBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to parse to type bundle: %w", err)
		}
	}
	return bundle, nil
}

// BundleProtoFromX509Authorities creates a Bundle API type from a trustdomain and
// a list of root CAs.
func bundleProtoFromX509Authorities(trustDomain string, rootCAs []*x509.Certificate) *api_types.Bundle {
	b := &api_types.Bundle{
		TrustDomain: trustDomain,
	}
	for _, rootCA := range rootCAs {
		b.X509Authorities = append(b.X509Authorities, &api_types.X509Certificate{
			Asn1: rootCA.Raw,
		})
	}
	return b
}

// protoFromSpiffeBundle converts a bundle from the given *spiffebundle.Bundle to *api_types.Bundle
func protoFromSpiffeBundle(bundle *spiffebundle.Bundle) (*api_types.Bundle, error) {
	resp := &api_types.Bundle{
		TrustDomain:     bundle.TrustDomain().Name(),
		X509Authorities: protoFromX509Certificates(bundle.X509Authorities()),
	}

	jwtAuthorities, err := protoFromJWTKeys(bundle.JWTAuthorities())
	if err != nil {
		return nil, err
	}
	resp.JwtAuthorities = jwtAuthorities

	if r, ok := bundle.RefreshHint(); ok {
		resp.RefreshHint = int64(r.Seconds())
	}

	if s, ok := bundle.SequenceNumber(); ok {
		resp.SequenceNumber = s
	}

	return resp, nil
}

// protoFromX509Certificates converts X.509 certificates from the given []*x509.Certificate to []*types.X509Certificate
func protoFromX509Certificates(certs []*x509.Certificate) []*api_types.X509Certificate {
	var resp []*api_types.X509Certificate
	for _, cert := range certs {
		resp = append(resp, &api_types.X509Certificate{
			Asn1: cert.Raw,
		})
	}

	return resp
}

// protoFromJWTKeys converts JWT keys from the given map[string]crypto.PublicKey to []*types.JWTKey
func protoFromJWTKeys(keys map[string]crypto.PublicKey) ([]*api_types.JWTKey, error) {
	var resp []*api_types.JWTKey

	for kid, key := range keys {
		pkixBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		resp = append(resp, &api_types.JWTKey{
			PublicKey: pkixBytes,
			KeyId:     kid,
		})
	}

	return resp, nil
}
