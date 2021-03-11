package entry

import (
	"flag"
	"fmt"

	"github.com/mitchellh/cli"

	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"

	"golang.org/x/net/context"
)

type countCommand struct{}

// NewCountCommand creates a new "count" subcommand for "entry" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(common_cli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "entry" command
// using the environment specified.
func NewCountCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(countCommand))
}

func (*countCommand) Name() string {
	return "entry count"
}

func (countCommand) Synopsis() string {
	return "Count registration entries"
}

//Run counts attested entries
func (c *countCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	entryClient := serverClient.NewEntryClient()
	countResponse, err := entryClient.CountEntries(ctx, &entry.CountEntriesRequest{})
	if err != nil {
		return err
	}

	count := int(countResponse.Count)
	msg := fmt.Sprintf("%d registration ", count)
	msg = util.Pluralizer(msg, "entry", "entries", count)
	env.Println(msg)

	return nil
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
}
