package localauthority

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewShowCommand creates a new "x509 show" subcommand for "localauthority" command.
func NewX509ShowCommand() cli.Command {
	return NewX509ShowCommandWithEnv(commoncli.DefaultEnv)
}

// NewX509ShowCommandWithEnv creates a new "x509 show" subcommand for "localauthority" command
// using the environment specified
func NewX509ShowCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &x509ShowCommand{env: env})
}

type x509ShowCommand struct {
	printer cliprinter.Printer

	env *commoncli.Env
}

func (c *x509ShowCommand) Name() string {
	return "localauthority x509 show"
}

func (*x509ShowCommand) Synopsis() string {
	return "Shows the local X.509 authorities"
}

func (c *x509ShowCommand) AppendFlags(f *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintX509Show)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority x509 show` CLI command
func (c *x509ShowCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.GetX509AuthorityState(ctx, &localauthorityv1.GetX509AuthorityStateRequest{})
	if err != nil {
		return fmt.Errorf("could not get X.509 authorities: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintX509Show(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.GetX509AuthorityStateResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Active X.509 authority:")
	if r.Active != nil {
		env.Printf("  Authority ID: %s\n", r.Active.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Active.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No active X.509 authority found")
	}
	env.Println()
	env.Println("Prepared X.509 authority:")
	if r.Prepared != nil {
		env.Printf("  Authority ID: %s\n", r.Prepared.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Prepared.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No prepared X.509 authority found")
	}
	env.Println()
	env.Println("Old X.509 authority:")
	if r.Old != nil {
		env.Printf("  Authority ID: %s\n", r.Old.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Old.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No old X.509 authority found")
	}
	return nil
}
