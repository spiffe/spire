package x509

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewX509ActivateCommand creates a new "x509 activate" subcommand for "localauthority" command.
func NewX509ActivateCommand() cli.Command {
	return NewX509ActivateCommandWithEnv(commoncli.DefaultEnv)
}

// NewX509ActivateCommandWithEnv creates a new "x509 activate" subcommand for "localauthority" command
// using the environment specified
func NewX509ActivateCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509ActivateCommand{env: env})
}

type x509ActivateCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *x509ActivateCommand) Name() string {
	return "localauthority x509 activate"
}

func (*x509ActivateCommand) Synopsis() string {
	return "Activates a prepared X.509 authority for use, which will cause it to be used for all X.509 signing operations serviced by this server going forward"
}

func (c *x509ActivateCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the X.509 authority to activate")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintX509Activate)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority x509 activate` CLI command
func (c *x509ActivateCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not activate X.509 authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *x509ActivateCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}

func prettyPrintX509Activate(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.ActivateX509AuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Activated X.509 authority:")
	if r.ActivatedAuthority == nil {
		return errors.New("internal error: expected to have activated X.509 authority information")
	}

	authoritycommon.PrettyPrintX509AuthorityState(env, r.ActivatedAuthority)

	return nil
}
