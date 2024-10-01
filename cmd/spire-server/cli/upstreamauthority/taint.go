package upstreamauthority

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewTaintCommand creates a new "upstreamauthority taint" subcommand for "upstreamauthority" command.
func NewTaintCommand() cli.Command {
	return newTaintCommand(commoncli.DefaultEnv)
}

// NewUpstreamauthorityTaintCommandWithEnv creates a new "upstreamauthority taint" subcommand for "upstreamauthority" command
// using the environment specified
func NewTaintCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &upstreamauthorityTaintCommand{env: env})
}

func newTaintCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &upstreamauthorityTaintCommand{env: env})
}

type upstreamauthorityTaintCommand struct {
	subjectKeyID string
	printer      cliprinter.Printer
	env          *commoncli.Env
}

func (c *upstreamauthorityTaintCommand) Name() string {
	return "upstreamauthority taint"
}

func (*upstreamauthorityTaintCommand) Synopsis() string {
	return "Marks the provided X.509 upstream authority as being tainted"
}

func (c *upstreamauthorityTaintCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.subjectKeyID, "subjectKeyID", "", "The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the upstream X.509 authority to taint")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintTaint)
}

// Run executes all logic associated with a single invocation of the
// `spire-server upstreamauthority taint` CLI command
func (c *upstreamauthorityTaintCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	client := serverClient.NewLocalAuthorityClient()
	resp, err := client.TaintX509UpstreamAuthority(ctx, &localauthorityv1.TaintX509UpstreamAuthorityRequest{
		SubjectKeyId: c.subjectKeyID,
	})
	if err != nil {
		return fmt.Errorf("could not taint X.509 upstream authority: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintTaint(env *commoncli.Env, results ...any) error {
	r, ok := results[0].(*localauthorityv1.TaintX509UpstreamAuthorityResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Println("Tainted X.509 upstream authority:")
	env.Printf("  Subject Key ID: %s\n", r.UpstreamAuthoritySubjectKeyId)
	return nil
}

func (c *upstreamauthorityTaintCommand) validate() error {
	if c.subjectKeyID == "" {
		return errors.New("the Subject Key ID of the X.509 upstream authority is required")
	}

	return nil
}
