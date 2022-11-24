package entry

import (
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"

	"golang.org/x/net/context"
)

type countCommand struct {
	printer cliprinter.Printer
	env     *commoncli.Env
}

// NewCountCommand creates a new "count" subcommand for "entry" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(commoncli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "entry" command
// using the environment specified.
func NewCountCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &countCommand{env: env})
}

func (*countCommand) Name() string {
	return "entry count"
}

func (*countCommand) Synopsis() string {
	return "Count registration entries"
}

// Run counts attested entries
func (c *countCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	entryClient := serverClient.NewEntryClient()
	countResponse, err := entryClient.CountEntries(ctx, &entryv1.CountEntriesRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(countResponse)
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintCount)
}

func (c *countCommand) prettyPrintCount(env *commoncli.Env, results ...interface{}) error {
	countResp, ok := results[0].(*entryv1.CountEntriesResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	count := int(countResp.Count)
	msg := fmt.Sprintf("%d registration ", count)
	msg = util.Pluralizer(msg, "entry", "entries", count)
	env.Println(msg)

	return nil
}
