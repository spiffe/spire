package entry

import (
	"errors"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc/codes"

	"golang.org/x/net/context"
)

// NewUpdateCommand creates a new "update" subcommand for "entry" command.
func NewUpdateCommand() cli.Command {
	return newUpdateCommand(common_cli.DefaultEnv)
}

func newUpdateCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(updateCommand))
}

type updateCommand struct {
	// Path to an optional data file. If set, other
	// opts will be ignored.
	path string

	// Registration entry id to update
	entryID string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// Workload parent spiffeID
	parentID string

	// Workload spiffeID
	spiffeID string

	// Whether or not the entry is for a downstream SPIRE server
	downstream bool

	// TTL for certificates issued to this workload
	ttl int

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// Whether or not the registration entry is for an "admin" workload
	admin bool

	// Expiry of entry
	entryExpiry int64

	// DNSNames entries for SVIDs based on this entry
	dnsNames StringsFlag
}

func (*updateCommand) Name() string {
	return "entry update"
}

func (*updateCommand) Synopsis() string {
	return "Updates registration entries"
}

func (c *updateCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.entryID, "entryID", "", "The Registration Entry ID of the record to update")
	f.StringVar(&c.parentID, "parentID", "", "The SPIFFE ID of this record's parent")
	f.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID that this record represents")
	f.IntVar(&c.ttl, "ttl", 0, "The lifetime, in seconds, for SVIDs issued based on this registration entry")
	f.StringVar(&c.path, "data", "", "Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.")
	f.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain to federate with. Can be used more than once")
	f.BoolVar(&c.admin, "admin", false, "If true, the SPIFFE ID in this entry will be granted access to the Registration API")
	f.BoolVar(&c.downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")
	f.Int64Var(&c.entryExpiry, "entryExpiry", 0, "An expiry, from epoch in seconds, for the resulting registration entry to be pruned")
	f.Var(&c.dnsNames, "dns", "A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once")
}

func (c *updateCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	var entries []*types.Entry
	var err error
	if c.path != "" {
		entries, err = parseFile(c.path)
	} else {
		entries, err = c.parseConfig()
	}
	if err != nil {
		return err
	}

	succeeded, failed, err := updateEntries(ctx, serverClient.NewEntryClient(), entries)
	if err != nil {
		return err
	}

	// Print entries that succeeded to be updated
	for _, e := range succeeded {
		printEntry(e.Entry, env.Printf)
	}

	// Print entries that failed to be updated
	for _, r := range failed {
		env.ErrPrintf("Failed to update the following entry (code: %s, msg: %q):\n",
			codes.Code(r.Status.Code),
			r.Status.Message)
		printEntry(r.Entry, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to update one or more entries")
	}

	return nil
}

// validate performs basic validation, even on fields that we
// have defaults defined for
func (c *updateCommand) validate() (err error) {
	// If a path is set, we have all we need
	if c.path != "" {
		return nil
	}

	if c.entryID == "" {
		return errors.New("entry ID is required")
	}

	if len(c.selectors) < 1 {
		return errors.New("at least one selector is required")
	}

	if c.parentID == "" {
		return errors.New("a parent ID is required")
	}

	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	if c.ttl < 0 {
		return errors.New("a positive TTL is required")
	}

	// make sure all SPIFFE ID's are well formed
	c.spiffeID, err = idutil.NormalizeSpiffeID(c.spiffeID, idutil.AllowAny())
	if err != nil {
		return err
	}
	c.parentID, err = idutil.NormalizeSpiffeID(c.parentID, idutil.AllowAny())
	if err != nil {
		return err
	}
	for i := range c.federatesWith {
		c.federatesWith[i], err = idutil.NormalizeSpiffeID(c.federatesWith[i], idutil.AllowAny())
		if err != nil {
			return err
		}
	}

	return nil
}

// parseConfig builds a registration entry from the given config
func (c *updateCommand) parseConfig() ([]*types.Entry, error) {
	parentID, err := idStringToProto(c.parentID)
	if err != nil {
		return nil, err
	}
	spiffeID, err := idStringToProto(c.spiffeID)
	if err != nil {
		return nil, err
	}

	e := &types.Entry{
		Id:         c.entryID,
		ParentId:   parentID,
		SpiffeId:   spiffeID,
		Ttl:        int32(c.ttl),
		Downstream: c.downstream,
		ExpiresAt:  c.entryExpiry,
		DnsNames:   c.dnsNames,
	}

	selectors := []*types.Selector{}
	for _, s := range c.selectors {
		cs, err := parseSelector(s)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, cs)
	}

	e.Selectors = selectors
	e.FederatesWith = c.federatesWith
	e.Admin = c.admin
	return []*types.Entry{e}, nil
}

func updateEntries(ctx context.Context, c entry.EntryClient, entries []*types.Entry) (succeeded, failed []*entry.BatchUpdateEntryResponse_Result, err error) {
	resp, err := c.BatchUpdateEntry(ctx, &entry.BatchUpdateEntryRequest{
		Entries: entries,
	})
	if err != nil {
		return nil, nil, err
	}

	for i, r := range resp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			// The Entry API does not include in the results the entries that
			// failed to be updated, so we populate them from the request data.
			r.Entry = entries[i]
			failed = append(failed, r)
		}
	}

	return succeeded, failed, nil
}
