package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"

	"golang.org/x/net/context"
)

// ShowConfig is a configuration struct for the
// `spire-server entry show` CLI command
type ShowConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	Selectors StringsFlag

	EntryID  string
	ParentID string
	SpiffeID string

	FederatesWith StringsFlag
	Downstream    bool
}

// Validate ensures that the values in ShowConfig are valid
func (sc *ShowConfig) Validate() error {
	// If entryID is given, it should be the only constraint
	if sc.EntryID != "" {
		if sc.ParentID != "" || sc.SpiffeID != "" || len(sc.Selectors) > 0 {
			return errors.New("the -entryID flag can't be combined with others")
		}
	}

	return nil
}

// ShowCLI is a struct which represents an invocation of the
// `spire-server entry show` CLI command
type ShowCLI struct {
	Client entry.EntryClient
	Config *ShowConfig

	Entries []*types.Entry
}

// Synopsis prints a description of the ShowCLI command
func (ShowCLI) Synopsis() string {
	return "Displays configured registration entries"
}

// Help prints a help message for the ShowCLI command
func (s ShowCLI) Help() string {
	err := s.loadConfig([]string{"-h"})
	return err.Error()
}

// Run executes all logic associated with a single invocation of the
// `spire-server entry show` CLI command
func (s *ShowCLI) Run(args []string) int {
	ctx := context.Background()

	err := s.loadConfig(args)
	if err != nil {
		fmt.Printf("Error parsing config options: %s", err)
		return 1
	}

	if s.Client == nil {
		srvCl, err := util.NewServerClient(s.Config.RegistrationUDSPath)
		if err != nil {
			fmt.Printf("Error creating new registration client: %v", err)
			return 1
		}
		s.Client = srvCl.NewEntryClient()
	}

	err = s.fetchEntries(ctx)
	if err != nil {
		return 1
	}

	commonutil.SortTypesEntries(s.Entries)
	s.filterByFederatedWith()
	s.printEntries()
	return 0
}

func (s *ShowCLI) fetchEntries(ctx context.Context) error {
	// If an Entry ID was specified, look it up directly
	if s.Config.EntryID != "" {
		err := s.fetchByEntryID(ctx, s.Config.EntryID)
		if err != nil {
			fmt.Printf("Error fetching entry ID %s: %s\n", s.Config.EntryID, err)
			return err
		}
		return nil
	}

	filter := &entry.ListEntriesRequest_Filter{}
	if s.Config.ParentID != "" {
		id, err := idStringToProto(s.Config.ParentID)
		if err != nil {
			fmt.Printf("Error parsing entry parent ID %q: %v", s.Config.ParentID, err)
			return err
		}
		filter.ByParentId = id
	}

	if s.Config.SpiffeID != "" {
		id, err := idStringToProto(s.Config.SpiffeID)
		if err != nil {
			fmt.Printf("Error parsing entry SPIFFE ID %q: %v", s.Config.SpiffeID, err)
			return err
		}
		filter.BySpiffeId = id
	}

	if len(s.Config.Selectors) != 0 {
		selectors := make([]*types.Selector, len(s.Config.Selectors))
		for i, sel := range s.Config.Selectors {
			selector, err := parseSelector(sel)
			if err != nil {
				return err
			}
			selectors[i] = selector
		}
		filter.BySelectors = &types.SelectorMatch{
			Selectors: selectors,
			Match:     types.SelectorMatch_MATCH_SUBSET,
		}
	}

	resp, err := s.Client.ListEntries(ctx, &entry.ListEntriesRequest{
		Filter: filter,
	})
	if err != nil {
		fmt.Printf("Error fetching entries: %v", err)
		return err
	}

	s.Entries = resp.Entries
	return nil
}

// fetchByEntryID uses the configured EntryID to fetch the appropriate registration entry
func (s *ShowCLI) fetchByEntryID(ctx context.Context, id string) error {
	entry, err := s.Client.GetEntry(ctx, &entry.GetEntryRequest{Id: id})
	if err != nil {
		return err
	}

	s.Entries = []*types.Entry{entry}
	return nil
}

// filterEntries evicts any entries from the stored slice which
// do not match every selector specified by the user
func (s *ShowCLI) filterByFederatedWith() {
	newSlice := []*types.Entry{}

	var federatedIDs map[string]bool
	if len(s.Config.FederatesWith) > 0 {
		federatedIDs = make(map[string]bool)
		for _, federatesWith := range s.Config.FederatesWith {
			federatedIDs[federatesWith] = true
		}
	}

	for _, e := range s.Entries {
		// If FederatesWith was specified, discard entries that don't match
		if federatedIDs != nil {
			found := false
			for _, federatesWith := range e.FederatesWith {
				if federatedIDs[federatesWith] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		newSlice = append(newSlice, e)
	}

	s.Entries = newSlice
}

func (s *ShowCLI) printEntries() {
	msg := fmt.Sprintf("Found %v ", len(s.Entries))
	msg = util.Pluralizer(msg, "entry", "entries", len(s.Entries))

	fmt.Println(msg)
	for _, e := range s.Entries {
		printEntry(e)
	}
}

func (s *ShowCLI) loadConfig(args []string) error {
	f := flag.NewFlagSet("entry show", flag.ContinueOnError)
	c := &ShowConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	f.StringVar(&c.EntryID, "entryID", "", "The Entry ID of the records to show")
	f.StringVar(&c.ParentID, "parentID", "", "The Parent ID of the records to show")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID of the records to show")
	f.BoolVar(&c.Downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")

	f.Var(&c.Selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.FederatesWith, "federatesWith", "SPIFFE ID of a trust domain an entry is federate with. Can be used more than once")

	err := f.Parse(args)
	if err != nil {
		return err
	}

	if c.ParentID != "" {
		c.ParentID, err = idutil.NormalizeSpiffeID(c.ParentID, idutil.AllowAny())
		if err != nil {
			return err
		}
	}
	if c.SpiffeID != "" {
		c.SpiffeID, err = idutil.NormalizeSpiffeID(c.SpiffeID, idutil.AllowAny())
		if err != nil {
			return err
		}
	}

	s.Config = c
	return nil
}
