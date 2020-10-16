package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc/codes"
)

// NewSetCommand creates a new "set" subcommand for "bundle" command.
func NewSetCommand() cli.Command {
	return newSetCommand(common_cli.DefaultEnv)
}

func newSetCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(setCommand))
}

type setCommand struct {
	// SPIFFE ID of the trust bundle
	id string

	// Path to the bundle on disk (optional). If empty, reads from stdin.
	path string

	format string
}

func (c *setCommand) Name() string {
	return "bundle set"
}

func (c *setCommand) Synopsis() string {
	return "Creates or updates bundle data"
}

func (c *setCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.path, "path", "", "Path to the bundle data")
	fs.StringVar(&c.format, "format", formatPEM, fmt.Sprintf("The format of the bundle data. Either %q or %q.", formatPEM, formatSPIFFE))
}

func (c *setCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id flag is required")
	}

	format, err := validateFormat(c.format)
	if err != nil {
		return err
	}

	id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return err
	}

	var federatedBundles []*types.Bundle

	bundleBytes, err := loadParamData(env.Stdin, c.path)
	if err != nil {
		return fmt.Errorf("unable to load bundle data: %v", err)
	}

	switch format {
	case formatPEM:
		rootCAs, err := pemutil.ParseCertificates(bundleBytes)
		if err != nil {
			return fmt.Errorf("unable to parse bundle data: %v", err)
		}

		federatedBundles = append(federatedBundles, bundleProtoFromX509Authorities(id, rootCAs))
	default:
		td, err := spiffeid.TrustDomainFromString(c.id)
		if err != nil {
			return err
		}

		spiffeBundle, err := spiffebundle.Parse(td, bundleBytes)
		if err != nil {
			return fmt.Errorf("unable to parse to spiffe bundle: %v", err)
		}

		typeBundle, err := protoFromSpiffeBundle(spiffeBundle)
		if err != nil {
			return fmt.Errorf("unable to parse to type bundle: %v", err)
		}

		federatedBundles = append(federatedBundles, typeBundle)
	}

	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.BatchSetFederatedBundle(ctx, &bundle.BatchSetFederatedBundleRequest{
		Bundle: federatedBundles,
	})
	if err != nil {
		return fmt.Errorf("failed to set federated bundle: %v", err)
	}

	result := resp.Results[0]
	switch result.Status.Code {
	case int32(codes.OK):
		env.Println("bundle set.")
		return nil
	default:
		return fmt.Errorf("failed to set federated bundle: %s", result.Status.Message)
	}
}
