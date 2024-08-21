package jwt

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewJWTShowCommand creates a new "jwt show" subcommand for "localauthority" command.
func NewJWTShowCommand() cli.Command {
	return NewJWTShowCommandWithEnv(commoncli.DefaultEnv)
}

// NewJWTShowCommandWithEnv creates a new "jwt show" subcommand for "localauthority" command
// using the environment specified
func NewJWTShowCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtShowCommand{env: env})
}

type jwtShowCommand struct {
	printer cliprinter.Printer

	env *commoncli.Env
}

func (c *jwtShowCommand) Name() string {
	return "localauthority jwt show"
}

func (*jwtShowCommand) Synopsis() string {
	return "Shows the local JWT authorities"
}

func (c *jwtShowCommand) AppendFlags(f *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintJWTShow)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority jwt show` CLI command
func (c *jwtShowCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.GetJWTAuthorityState(ctx, &localauthorityv1.GetJWTAuthorityStateRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintJWTShow(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.GetJWTAuthorityStateResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Active JWT authority:")
	if r.Active != nil {
		env.Printf("  Authority ID: %s\n", r.Active.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Active.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No active JWT authority found")
	}
	env.Println()
	env.Println("Prepared JWT authority:")
	if r.Prepared != nil {
		env.Printf("  Authority ID: %s\n", r.Prepared.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Prepared.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No prepared JWT authority found")
	}
	env.Println()
	env.Println("Old JWT authority:")
	if r.Old != nil {
		env.Printf("  Authority ID: %s\n", r.Old.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.Old.ExpiresAt, 0).UTC())
	} else {
		env.Println("  No old JWT authority found")
	}
	return nil
}
