package entry

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
)

// NewCreateCommand creates a new "create" subcommand for "entry" command.
func NewCreateCommand() cli.Command {
	return newCreateCommand(commoncli.DefaultEnv)
}

func newCreateCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &createCommand{env: env})
}

type createCommand struct {
	// Path to an optional data file. If set, other
	// opts will be ignored.
	path string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// Registration entry ID
	entryID string

	// Workload parent spiffeID
	parentID string

	// Workload spiffeID
	spiffeID string

	// Entry hint, used to disambiguate entries with the same SPIFFE ID
	hint string

	// TTL for x509 SVIDs issued to this workload
	x509SVIDTTL int

	// TTL for JWT SVIDs issued to this workload
	jwtSVIDTTL int

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// whether the registration entry is for an "admin" workload
	admin bool

	// whether the entry is for a downstream SPIRE server
	downstream bool

	// whether the entry represents a node or group of nodes
	node bool

	// Expiry of entry
	entryExpiry int64

	// DNSNames entries for SVIDs based on this entry
	dnsNames StringsFlag

	// storeSVID determines if the issued SVID must be stored through an SVIDStore plugin
	storeSVID bool

	printer cliprinter.Printer

	env *commoncli.Env
}

func (*createCommand) Name() string {
	return "entry create"
}

func (*createCommand) Synopsis() string {
	return "Creates registration entries"
}

func (c *createCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.entryID, "entryID", "", "A custom ID for this registration entry (optional). If not set, a new entry ID will be generated")
	f.StringVar(&c.parentID, "parentID", "", "The SPIFFE ID of this record's parent")
	f.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID that this record represents")
	f.IntVar(&c.x509SVIDTTL, "x509SVIDTTL", 0, "The lifetime, in seconds, for x509-SVIDs issued based on this registration entry.")
	f.IntVar(&c.jwtSVIDTTL, "jwtSVIDTTL", 0, "The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry.")
	f.StringVar(&c.path, "data", "", "Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.")
	f.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain to federate with. Can be used more than once")
	f.BoolVar(&c.node, "node", false, "If set, this entry will be applied to matching nodes rather than workloads")
	f.BoolVar(&c.admin, "admin", false, "If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs")
	f.BoolVar(&c.storeSVID, "storeSVID", false, "A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin")
	f.BoolVar(&c.downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")
	f.Int64Var(&c.entryExpiry, "entryExpiry", 0, "An expiry, from epoch in seconds, for the resulting registration entry to be pruned")
	f.Var(&c.dnsNames, "dns", "A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once")
	f.StringVar(&c.hint, "hint", "", "The entry hint, used to disambiguate entries with the same SPIFFE ID")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintCreate)
}

func (c *createCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient serverutil.ServerClient) error {
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

	resp, err := createEntries(ctx, serverClient.NewEntryClient(), entries)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// validate performs basic validation, even on fields that we
// have defaults defined for.
func (c *createCommand) validate() (err error) {
	// If a path is set, we have all we need
	if c.path != "" {
		return nil
	}

	if len(c.selectors) < 1 {
		return errors.New("at least one selector is required")
	}

	if c.node && len(c.federatesWith) > 0 {
		return errors.New("node entries can not federate")
	}

	if c.parentID == "" && !c.node {
		return errors.New("a parent ID is required if the node flag is not set")
	}

	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	if c.x509SVIDTTL < 0 {
		return errors.New("a positive x509-SVID TTL is required")
	}

	if c.jwtSVIDTTL < 0 {
		return errors.New("a positive JWT-SVID TTL is required")
	}

	return nil
}

// parseConfig builds a registration entry from the given config
func (c *createCommand) parseConfig() ([]*types.Entry, error) {
	spiffeID, err := idStringToProto(c.spiffeID)
	if err != nil {
		return nil, err
	}

	parentID, err := getParentID(c, spiffeID.TrustDomain)
	if err != nil {
		return nil, err
	}

	x509SvidTTL, err := util.CheckedCast[int32](c.x509SVIDTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid value for X509 SVID TTL: %w", err)
	}

	jwtSvidTTL, err := util.CheckedCast[int32](c.jwtSVIDTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid value for JWT SVID TTL: %w", err)
	}

	e := &types.Entry{
		Id:          c.entryID,
		ParentId:    parentID,
		SpiffeId:    spiffeID,
		Downstream:  c.downstream,
		ExpiresAt:   c.entryExpiry,
		DnsNames:    c.dnsNames,
		StoreSvid:   c.storeSVID,
		X509SvidTtl: x509SvidTTL,
		JwtSvidTtl:  jwtSvidTTL,
		Hint:        c.hint,
	}

	selectors := []*types.Selector{}
	for _, s := range c.selectors {
		cs, err := serverutil.ParseSelector(s)
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

func createEntries(ctx context.Context, c entryv1.EntryClient, entries []*types.Entry) (resp *entryv1.BatchCreateEntryResponse, err error) {
	resp, err = c.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: entries})
	if err != nil {
		return
	}

	for i, r := range resp.Results {
		if r.Status.Code != int32(codes.OK) {
			// The Entry API does not include in the results the entries that
			// failed to be created, so we populate them from the request data.
			r.Entry = entries[i]
		}
	}

	return
}

func getParentID(config *createCommand, td string) (*types.SPIFFEID, error) {
	// If the node flag is set, then set the Parent ID to the server's expected SPIFFE ID
	if config.node {
		return &types.SPIFFEID{
			TrustDomain: td,
			Path:        idutil.ServerIDPath,
		}, nil
	}
	return idStringToProto(config.parentID)
}

func prettyPrintCreate(env *commoncli.Env, results ...any) error {
	var succeeded, failed []*entryv1.BatchCreateEntryResponse_Result
	createResp, ok := results[0].(*entryv1.BatchCreateEntryResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	for _, r := range createResp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			failed = append(failed, r)
		}
	}

	for _, r := range succeeded {
		printEntry(r.Entry, env.Printf)
	}

	for _, r := range failed {
		env.ErrPrintf("Failed to create the following entry (code: %s, msg: %q):\n",
			util.MustCast[codes.Code](r.Status.Code),
			r.Status.Message)
		printEntry(r.Entry, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to create one or more entries")
	}

	return nil
}
