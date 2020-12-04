package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"

	"golang.org/x/net/context"
)

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

	filteredEntries := c.filterByFederatedWith(entries)
	commonutil.SortTypesEntries(filteredEntries)
	printEntries(filteredEntries, env)
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

func (c *showCommand) fetchEntries(ctx context.Context, client entry.EntryClient) ([]*types.Entry, error) {
	// If an Entry ID was specified, look it up directly
	if c.entryID != "" {
		entry, err := c.fetchByEntryID(ctx, c.entryID, client)
		if err != nil {
			return nil, fmt.Errorf("error fetching entry ID %s: %s", c.entryID, err)
		}
		return []*types.Entry{entry}, nil
	}

	filter := &entry.ListEntriesRequest_Filter{}
	if c.parentID != "" {
		id, err := idStringToProto(c.parentID)
		if err != nil {
			return nil, fmt.Errorf("error parsing parent ID %q: %v", c.parentID, err)
		}
		filter.ByParentId = id
	}

	if c.spiffeID != "" {
		id, err := idStringToProto(c.spiffeID)
		if err != nil {
			return nil, fmt.Errorf("error parsing SPIFFE ID %q: %v", c.spiffeID, err)
		}
		filter.BySpiffeId = id
	}

	if len(c.selectors) != 0 {
		selectors := make([]*types.Selector, len(c.selectors))
		for i, sel := range c.selectors {
			selector, err := parseSelector(sel)
			if err != nil {
				return nil, fmt.Errorf("error parsing selectors: %v", err)
			}
			selectors[i] = selector
		}
		filter.BySelectors = &types.SelectorMatch{
			Selectors: selectors,
			Match:     types.SelectorMatch_MATCH_EXACT,
		}
	}

	resp, err := client.ListEntries(ctx, &entry.ListEntriesRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching entries: %v", err)
	}

	return resp.Entries, nil
}

// fetchByEntryID uses the configured EntryID to fetch the appropriate registration entry
func (c *showCommand) fetchByEntryID(ctx context.Context, id string, client entry.EntryClient) (*types.Entry, error) {
	entry, err := client.GetEntry(ctx, &entry.GetEntryRequest{Id: id})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

// filterByFederatedWith evicts any value from the given entries slice that does
// not contain at least one of the federated trust domains specified in the
// federatesWith slice.
func (c *showCommand) filterByFederatedWith(entries []*types.Entry) []*types.Entry {
	// Build map for quick search
	var federatedIDs map[string]bool
	if len(c.federatesWith) > 0 {
		federatedIDs = make(map[string]bool)
		for _, federatesWith := range c.federatesWith {
			federatedIDs[federatesWith] = true
		}
	}

	// Filter slice in place
	idx := 0
	for _, e := range entries {
		if keepEntry(e, federatedIDs) {
			entries[idx] = e
			idx++
		}
	}

	return entries[:idx]
}

func keepEntry(e *types.Entry, federatedIDs map[string]bool) bool {
	// If FederatesWith was specified, discard entries that don't match
	if federatedIDs == nil {
		return true
	}

	for _, federatesWith := range e.FederatesWith {
		if federatedIDs[federatesWith] {
			return true
		}
	}

	return false
}

func printEntries(entries []*types.Entry, env *common_cli.Env) {
	msg := fmt.Sprintf("Found %v ", len(entries))
	msg = util.Pluralizer(msg, "entry", "entries", len(entries))

	env.Println(msg)
	for _, e := range entries {
		printEntry(e, env.Printf)
	}
}
