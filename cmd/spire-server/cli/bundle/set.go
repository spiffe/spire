package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
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
	fs.StringVar(&c.format, "format", util.FormatPEM, fmt.Sprintf("The format of the bundle data. Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
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

	bundleBytes, err := loadParamData(env.Stdin, c.path)
	if err != nil {
		return fmt.Errorf("unable to load bundle data: %w", err)
	}

	bundle, err := util.ParseBundle(bundleBytes, format, id)
	if err != nil {
		return err
	}

	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.BatchSetFederatedBundle(ctx, &bundlev1.BatchSetFederatedBundleRequest{
		Bundle: []*types.Bundle{bundle},
	})
	if err != nil {
		return fmt.Errorf("failed to set federated bundle: %w", err)
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
