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

// NewJWTActivateCommand creates a new "jwt activate" subcommand for "localauthority" command.
func NewJWTActivateCommand() cli.Command {
	return NewJWTActivateCommandWithEnv(commoncli.DefaultEnv)
}

// NewJWTActivateCommandWithEnv creates a new "jwt activate" subcommand for "localauthority" command
// using the environment specified
func NewJWTActivateCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtActivateCommand{env: env})
}

type jwtActivateCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *jwtActivateCommand) Name() string {
	return "localauthority jwt activate"
}

func (*jwtActivateCommand) Synopsis() string {
	return "Activates a prepared JWT authority for use, which will cause it to be used for all JWT signing operations serviced by this server going forward"
}

func (c *jwtActivateCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the JWT authority to activate")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintJWTActivate)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority jwt activate` CLI command
func (c *jwtActivateCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.ActivateJWTAuthority(ctx, &localauthorityv1.ActivateJWTAuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not activate JWT authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *jwtActivateCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}

func prettyPrintJWTActivate(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.ActivateJWTAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Activated JWT authority:")
	if r.ActivatedAuthority == nil {
		return errors.New("internal error: expected to have activated JWT authority information")
	}
	authoritycommon.PrettyPrintJWTAuthorityState(env, r.ActivatedAuthority)

	return nil
}
