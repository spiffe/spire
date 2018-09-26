package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"
)

const (
	deleteBundleRestrict   = "restrict"
	deleteBundleDissociate = "dissociate"
	deleteBundleDelete     = "delete"
)

// NewDeleteCommand creates a new "delete" subcommand for "bundle" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(defaultEnv, newClients)
}

func newDeleteCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(deleteCommand))
}

type deleteCommand struct {
	// SPIFFE ID of the trust domain bundle
	id string

	// Deletion mode.
	mode string
}

func (c *deleteCommand) name() string {
	return "bundle delete"
}

func (c *deleteCommand) synopsis() string {
	return "Deletes bundle data"
}

func (c *deleteCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.mode, "mode", deleteBundleRestrict, fmt.Sprintf("Deletion mode: one of %s, %s, or %s", deleteBundleRestrict, deleteBundleDelete, deleteBundleDissociate))
}

func (c *deleteCommand) run(ctx context.Context, env *env, clients *clients) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return err
	}

	mode, err := deleteModeFromFlag(c.mode)
	if err != nil {
		return err
	}

	if _, err := clients.r.DeleteFederatedBundle(ctx, &registration.DeleteFederatedBundleRequest{
		Id:   id,
		Mode: mode,
	}); err != nil {
		return err
	}

	return env.Println("bundle deleted.")
}

func deleteModeFromFlag(mode string) (registration.DeleteFederatedBundleRequest_Mode, error) {
	switch mode {
	case "", deleteBundleRestrict:
		return registration.DeleteFederatedBundleRequest_RESTRICT, nil
	case deleteBundleDissociate:
		return registration.DeleteFederatedBundleRequest_DISSOCIATE, nil
	case deleteBundleDelete:
		return registration.DeleteFederatedBundleRequest_DELETE, nil
	default:
		return registration.DeleteFederatedBundleRequest_RESTRICT, fmt.Errorf("unsupported mode %q", mode)
	}
}
