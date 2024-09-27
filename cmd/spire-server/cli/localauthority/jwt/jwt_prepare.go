package jwt

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

// NewJWTPrepareCommand creates a new "jwt prepare" subcommand for "localauthority" command.
func NewJWTPrepareCommand() cli.Command {
	return NewJWTPrepareCommandWithEnv(commoncli.DefaultEnv)
}

// NewJWTPrepareCommandWithEnv creates a new "jwt prepare" subcommand for "localauthority" command
// using the environment specified
func NewJWTPrepareCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtPrepareCommand{env: env})
}

type jwtPrepareCommand struct {
	printer cliprinter.Printer
	env     *commoncli.Env
}

func (c *jwtPrepareCommand) Name() string {
	return "localauthority jwt prepare"
}

func (*jwtPrepareCommand) Synopsis() string {
	return "Prepares a new JWT authority for use by generating a new key and injecting it into the bundle"
}

func (c *jwtPrepareCommand) AppendFlags(f *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintJWTPrepare)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority jwt prepare` CLI command
func (c *jwtPrepareCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.PrepareJWTAuthority(ctx, &localauthorityv1.PrepareJWTAuthorityRequest{})
	if err != nil {
		return fmt.Errorf("could not prepare JWT authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintJWTPrepare(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.PrepareJWTAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Prepared JWT authority:")
	if r.PreparedAuthority == nil {
		return errors.New("internal error: expected to have prepared JWT authority information")
	}
	authoritycommon.PrettyPrintJWTAuthorityState(env, r.PreparedAuthority)

	return nil
}
