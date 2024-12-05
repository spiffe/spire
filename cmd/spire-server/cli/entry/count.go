package entry

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type countCommand struct {
	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// Workload parent spiffeID
	parentID string

	// Workload spiffeID
	spiffeID string

	// Entry hint
	hint string

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// Whether the entry is for a downstream SPIRE server
	downstream bool

	// Match used when filtering by federates with
	matchFederatesWithOn string

	// Match used when filtering by selectors
	matchSelectorsOn string

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
func (c *countCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	entryClient := serverClient.NewEntryClient()

	filter := &entryv1.CountEntriesRequest_Filter{}
	if c.parentID != "" {
		id, err := idStringToProto(c.parentID)
		if err != nil {
			return fmt.Errorf("error parsing parent ID %q: %w", c.parentID, err)
		}
		filter.ByParentId = id
	}

	if c.spiffeID != "" {
		id, err := idStringToProto(c.spiffeID)
		if err != nil {
			return fmt.Errorf("error parsing SPIFFE ID %q: %w", c.spiffeID, err)
		}
		filter.BySpiffeId = id
	}

	if len(c.selectors) != 0 {
		matchSelectorBehavior, err := parseToSelectorMatch(c.matchSelectorsOn)
		if err != nil {
			return err
		}

		selectors := make([]*types.Selector, len(c.selectors))
		for i, sel := range c.selectors {
			selector, err := util.ParseSelector(sel)
			if err != nil {
				return fmt.Errorf("error parsing selectors: %w", err)
			}
			selectors[i] = selector
		}
		filter.BySelectors = &types.SelectorMatch{
			Selectors: selectors,
			Match:     matchSelectorBehavior,
		}
	}

	filter.ByDownstream = wrapperspb.Bool(c.downstream)

	if len(c.federatesWith) > 0 {
		matchFederatesWithBehavior, err := parseToFederatesWithMatch(c.matchFederatesWithOn)
		if err != nil {
			return err
		}

		filter.ByFederatesWith = &types.FederatesWithMatch{
			TrustDomains: c.federatesWith,
			Match:        matchFederatesWithBehavior,
		}
	}

	if c.hint != "" {
		filter.ByHint = wrapperspb.String(c.hint)
	}

	countResponse, err := entryClient.CountEntries(ctx, &entryv1.CountEntriesRequest{
		Filter: filter,
	})

	if err != nil {
		return err
	}

	return c.printer.PrintProto(countResponse)
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.parentID, "parentID", "", "The Parent ID of the records to count")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the records to count")
	fs.BoolVar(&c.downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")
	fs.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	fs.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain an entry is federate with. Can be used more than once")
	fs.StringVar(&c.matchFederatesWithOn, "matchFederatesWithOn", "superset", "The match mode used when filtering by federates with. Options: exact, any, superset and subset")
	fs.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	fs.StringVar(&c.hint, "hint", "", "The Hint of the records to count (optional)")

	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintCount)
}

func (c *countCommand) prettyPrintCount(env *commoncli.Env, results ...any) error {
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
