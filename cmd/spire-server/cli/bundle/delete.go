package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"google.golang.org/grpc/codes"
)

const (
	deleteBundleRestrict   = "restrict"
	deleteBundleDissociate = "dissociate"
	deleteBundleDelete     = "delete"
)

// NewDeleteCommand creates a new "delete" subcommand for "bundle" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(common_cli.DefaultEnv)
}

func newDeleteCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(deleteCommand))
}

type deleteCommand struct {
	// SPIFFE ID of the trust domain bundle
	id string

	// Deletion mode
	mode string
}

func (c *deleteCommand) Name() string {
	return "bundle delete"
}

func (c *deleteCommand) Synopsis() string {
	return "Deletes bundle data"
}

func (c *deleteCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.mode, "mode", deleteBundleRestrict, fmt.Sprintf("Deletion mode: one of %s, %s, or %s", deleteBundleRestrict, deleteBundleDelete, deleteBundleDissociate))
}

func (c *deleteCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	id, err := spiffeid.FromString(c.id)
	if err != nil {
		return fmt.Errorf("%q is not a valid SPIFFE ID: %s", c.id, err)
	}
	err = idutil.ValidateSpiffeID(id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return err
	}

	mode, err := deleteModeFromFlag(c.mode)
	if err != nil {
		return err
	}

	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.BatchDeleteFederatedBundle(ctx, &bundle.BatchDeleteFederatedBundleRequest{
		Mode: mode,
		TrustDomains: []string{
			id.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete federated bundle: %w", err)
	}
	result := resp.Results[0]
	switch result.Status.Code {
	case int32(codes.OK):
		env.Println("bundle deleted.")
		return nil
	default:
		return fmt.Errorf("failed to delete federated bundle %q: %s", result.TrustDomain, result.Status.Message)
	}
}

func deleteModeFromFlag(mode string) (bundle.BatchDeleteFederatedBundleRequest_Mode, error) {
	switch mode {
	case "", deleteBundleRestrict:
		return bundle.BatchDeleteFederatedBundleRequest_RESTRICT, nil
	case deleteBundleDissociate:
		return bundle.BatchDeleteFederatedBundleRequest_DISSOCIATE, nil
	case deleteBundleDelete:
		return bundle.BatchDeleteFederatedBundleRequest_DELETE, nil
	default:
		return bundle.BatchDeleteFederatedBundleRequest_RESTRICT, fmt.Errorf("unsupported mode %q", mode)
	}
}
