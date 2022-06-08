package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	commonutil "github.com/spiffe/spire/pkg/common/util"

	"golang.org/x/net/context"
)

const listEntriesRequestPageSize = 500

// NewShowCommand creates a new "show" subcommand for "entry" command.
func NewShowCommand() cli.Command {
	return newShowCommand(common_cli.DefaultEnv)
}

func newShowCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(showCommand))
}

type showCommand struct {
	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// ID of the entry to be shown
	entryID string

	// Workload parent spiffeID
	parentID string

	// Workload spiffeID
	spiffeID string

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// Whether or not the entry is for a downstream SPIRE server
	downstream bool

	// Match used when filtering by federates with
	matchFederatesWithOn string

	// Match used when filtering by selectors
	matchSelectorsOn string
}

func (c *showCommand) Name() string {
	return "entry show"
}

func (*showCommand) Synopsis() string {
	return "Displays configured registration entries"
}

func (c *showCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.entryID, "entryID", "", "The Entry ID of the records to show")
	f.StringVar(&c.parentID, "parentID", "", "The Parent ID of the records to show")
	f.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the records to show")
	f.BoolVar(&c.downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")
	f.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain an entry is federate with. Can be used more than once")
	f.StringVar(&c.matchFederatesWithOn, "matchFederatesWithOn", "superset", "The match mode used when filtering by federates with. Options: exact, any, superset and subset")
	f.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
}

// Run executes all logic associated with a single invocation of the
// `spire-server entry show` CLI command
func (c *showCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	entries, err := c.fetchEntries(ctx, serverClient.NewEntryClient())
	if err != nil {
		return err
	}

	commonutil.SortTypesEntries(entries)
	printEntries(entries, env)
	return nil
}

// validate ensures that the values in showCommand are valid
func (c *showCommand) validate() error {
	// If entryID is given, it should be the only constraint
	if c.entryID != "" {
		if c.parentID != "" || c.spiffeID != "" || len(c.selectors) > 0 {
			return errors.New("the -entryID flag can't be combined with others")
		}
	}

	return nil
}

func (c *showCommand) fetchEntries(ctx context.Context, client entryv1.EntryClient) ([]*types.Entry, error) {
	// If an Entry ID was specified, look it up directly
	if c.entryID != "" {
		entry, err := c.fetchByEntryID(ctx, c.entryID, client)
		if err != nil {
			return nil, fmt.Errorf("error fetching entry ID %s: %w", c.entryID, err)
		}
		return []*types.Entry{entry}, nil
	}

	filter := &entryv1.ListEntriesRequest_Filter{}
	if c.parentID != "" {
		id, err := idStringToProto(c.parentID)
		if err != nil {
			return nil, fmt.Errorf("error parsing parent ID %q: %w", c.parentID, err)
		}
		filter.ByParentId = id
	}

	if c.spiffeID != "" {
		id, err := idStringToProto(c.spiffeID)
		if err != nil {
			return nil, fmt.Errorf("error parsing SPIFFE ID %q: %w", c.spiffeID, err)
		}
		filter.BySpiffeId = id
	}

	if len(c.selectors) != 0 {
		matchSelectorBehavior, err := parseToSelectorMatch(c.matchSelectorsOn)
		if err != nil {
			return nil, err
		}

		selectors := make([]*types.Selector, len(c.selectors))
		for i, sel := range c.selectors {
			selector, err := util.ParseSelector(sel)
			if err != nil {
				return nil, fmt.Errorf("error parsing selectors: %w", err)
			}
			selectors[i] = selector
		}
		filter.BySelectors = &types.SelectorMatch{
			Selectors: selectors,
			Match:     matchSelectorBehavior,
		}
	}

	if len(c.federatesWith) > 0 {
		matchFederatesWithBehavior, err := parseToFederatesWithMatch(c.matchFederatesWithOn)
		if err != nil {
			return nil, err
		}

		filter.ByFederatesWith = &types.FederatesWithMatch{
			TrustDomains: c.federatesWith,
			Match:        matchFederatesWithBehavior,
		}
	}

	pageToken := ""
	var entries []*types.Entry

	for {
		resp, err := client.ListEntries(ctx, &entryv1.ListEntriesRequest{
			PageSize:  listEntriesRequestPageSize,
			PageToken: pageToken,
			Filter:    filter,
		})
		if err != nil {
			return nil, fmt.Errorf("error fetching entries: %w", err)
		}
		entries = append(entries, resp.Entries...)
		if pageToken = resp.NextPageToken; pageToken == "" {
			break
		}
	}

	return entries, nil
}

// fetchByEntryID uses the configured EntryID to fetch the appropriate registration entry
func (c *showCommand) fetchByEntryID(ctx context.Context, id string, client entryv1.EntryClient) (*types.Entry, error) {
	entry, err := client.GetEntry(ctx, &entryv1.GetEntryRequest{Id: id})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func printEntries(entries []*types.Entry, env *common_cli.Env) {
	msg := fmt.Sprintf("Found %v ", len(entries))
	msg = util.Pluralizer(msg, "entry", "entries", len(entries))

	env.Println(msg)
	for _, e := range entries {
		printEntry(e, env.Printf)
	}
}

func parseToSelectorMatch(match string) (types.SelectorMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.SelectorMatch_MATCH_EXACT, nil
	case "any":
		return types.SelectorMatch_MATCH_ANY, nil
	case "superset":
		return types.SelectorMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.SelectorMatch_MATCH_SUBSET, nil
	default:
		return types.SelectorMatch_MATCH_SUPERSET, fmt.Errorf("match behavior %q unknown", match)
	}
}

func parseToFederatesWithMatch(match string) (types.FederatesWithMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.FederatesWithMatch_MATCH_EXACT, nil
	case "any":
		return types.FederatesWithMatch_MATCH_ANY, nil
	case "superset":
		return types.FederatesWithMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.FederatesWithMatch_MATCH_SUBSET, nil
	default:
		return types.FederatesWithMatch_MATCH_SUPERSET, fmt.Errorf("match behavior %q unknown", match)
	}
}
