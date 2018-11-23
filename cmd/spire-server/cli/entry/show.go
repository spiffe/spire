package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"

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
			return errors.New("The -entryID flag can't be combined with others")
		}
	}

	return nil
}

// ShowCLI is a struct which represents an invocation of the
// `spire-server entry show` CLI command
type ShowCLI struct {
	Client registration.RegistrationClient
	Config *ShowConfig

	Entries []*common.RegistrationEntry
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
		s.Client, err = util.NewRegistrationClient(s.Config.RegistrationUDSPath)
		if err != nil {
			fmt.Printf("Error creating new registration client: %v", err)
			return 1
		}
	}

	// If an Entry ID was specified, look it up directly then exit
	if s.Config.EntryID != "" {
		err = s.fetchByEntryID(ctx, s.Config.EntryID)
		if err != nil {
			fmt.Printf("Error fetching entry ID %s: %s\n", s.Config.EntryID, err)
			return 1
		}

		s.printEntries()
		return 0
	}

	// If we didn't get any args, fetch everything then exit
	if s.Config.ParentID == "" && s.Config.SpiffeID == "" && len(s.Config.Selectors) == 0 {
		err = s.fetchAllEntries(ctx)
		if err != nil {
			fmt.Printf("Error fetching entries: %s\n", err)
			return 1
		}

		s.filterEntries()
		s.printEntries()
		return 0
	}

	// Fetch all records matching each constraint, then find and
	// print the intersection at the end.
	err = s.fetchByParentID(ctx)
	if err != nil {
		fmt.Printf("Error fetching by parent ID: %s", err)
		return 1
	}

	err = s.fetchBySpiffeID(ctx)
	if err != nil {
		fmt.Printf("Error fetching by SPIFFE ID: %s", err)
		return 1
	}

	err = s.fetchBySelectors(ctx)
	if err != nil {
		fmt.Printf("Error fetching by selectors: %s", err)
		return 1
	}

	s.filterEntries()
	s.printEntries()
	return 0
}

func (s *ShowCLI) fetchAllEntries(ctx context.Context) error {
	var err error
	entries, err := s.Client.FetchEntries(ctx, &common.Empty{})
	if err != nil {
		return err
	}

	s.Entries = entries.Entries
	return nil
}

// fetchByEntryID uses the configured EntryID to fetch the appropriate registration entry
func (s *ShowCLI) fetchByEntryID(ctx context.Context, id string) error {
	regID := &registration.RegistrationEntryID{Id: id}
	entry, err := s.Client.FetchEntry(ctx, regID)
	if err != nil {
		return err
	}

	s.Entries = []*common.RegistrationEntry{entry}
	return nil
}

// fetchByParentID appends registration entries which match the configured
// Parent ID to `entries`
func (s *ShowCLI) fetchByParentID(ctx context.Context) error {
	if s.Config.ParentID != "" {
		parentID := &registration.ParentID{Id: s.Config.ParentID}
		entries, err := s.Client.ListByParentID(ctx, parentID)
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries.Entries...)
	}

	return nil
}

// fetchBySpiffeID appends registration entries which match the configured
// SPIFFE ID to `entries`
func (s *ShowCLI) fetchBySpiffeID(ctx context.Context) error {
	if s.Config.SpiffeID != "" {
		spiffeID := &registration.SpiffeID{Id: s.Config.SpiffeID}
		entries, err := s.Client.ListBySpiffeID(ctx, spiffeID)
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries.Entries...)
	}

	return nil
}

// fetchBySelectors fetches all registration entries containing the full
// set of configured selectors, appending them to `entries`
func (s *ShowCLI) fetchBySelectors(ctx context.Context) error {
	for _, sel := range s.Config.Selectors {
		selector, err := parseSelector(sel)
		if err != nil {
			return err
		}

		entries, err := s.Client.ListBySelector(ctx, selector)
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries.Entries...)
	}

	return nil
}

// filterEntries evicts any entries from the stored slice which
// do not match every selector specified by the user
func (s *ShowCLI) filterEntries() {
	newSlice := []*common.RegistrationEntry{}
	// Map used to skip duplicated entries.
	matchingEntries := map[string]*common.RegistrationEntry{}

	var federatedIDs map[string]bool
	if len(s.Config.FederatesWith) > 0 {
		federatedIDs = make(map[string]bool)
		for _, federatesWith := range s.Config.FederatesWith {
			federatedIDs[federatesWith] = true
		}
	}

	for _, e := range s.Entries {
		match, _ := hasSelectors(e, s.Config.Selectors)
		if !match {
			continue
		}

		// If SpiffeID was specified, discard entries that don't match.
		if s.Config.SpiffeID != "" && e.SpiffeId != s.Config.SpiffeID {
			continue
		}

		// If ParentID was specified, discard entries that don't match.
		if s.Config.ParentID != "" && e.ParentId != s.Config.ParentID {
			continue
		}

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

		// If this entry wasn't matched before, save it.
		if _, ok := matchingEntries[e.EntryId]; !ok {
			matchingEntries[e.EntryId] = e
			newSlice = append(newSlice, e)
		}
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
	f.BoolVar(&c.Downstream, "downstream", false, "A boolean value to enable signing CA CSR for heirarchical spire server")

	f.Var(&c.Selectors, "selector", "A colon-delimeted type:value selector. Can be used more than once")
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
