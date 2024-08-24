package jwt

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

// NewJWTActivateCommand creates a new "jwt revoke" subcommand for "localauthority" command.
func NewJWTRevokeCommand() cli.Command {
	return NewJWTRevokeCommandWithEnv(commoncli.DefaultEnv)
}

// NewJWTActivateCommandWithEnv creates a new "jwt revoke" subcommand for "localauthority" command
// using the environment specified
func NewJWTRevokeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &jwtRevokeCommand{env: env})
}

type jwtRevokeCommand struct {
	authorityID string
	printer     cliprinter.Printer
	env         *commoncli.Env
}

func (c *jwtRevokeCommand) Name() string {
	return "localauthority jwt revoke"
}

func (*jwtRevokeCommand) Synopsis() string {
	return "Revokes the previously active JWT authority by removing it from the bundle and propagating this update throughout the cluster"
}

func (c *jwtRevokeCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "The authority ID of the JWT authority to revoke")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintJWTRevoke)
}

// Run executes all logic associated with a single invocation of the
// `spire-server localauthority jwt revoke` CLI command
func (c *jwtRevokeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.RevokeJWTAuthority(ctx, &localauthorityv1.RevokeJWTAuthorityRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return fmt.Errorf("could not revoke JWT authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *jwtRevokeCommand) validate() error {
	if c.authorityID == "" {
		return errors.New("an authority ID is required")
	}

	return nil
}

func prettyPrintJWTRevoke(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.RevokeJWTAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Revoked JWT authority:")
	if r.RevokedAuthority != nil {
		env.Printf("  Authority ID: %s\n", r.RevokedAuthority.AuthorityId)
		env.Printf("  Expires at: %s\n", time.Unix(r.RevokedAuthority.ExpiresAt, 0).UTC())
	} else {
		return errors.New("internal error: expected to have revoked JWT authority information")
	}

	return nil
}
