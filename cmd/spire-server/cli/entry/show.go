package entry

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"
)

type ShowConfig struct {
	// Address of SPIRE server
	Addr string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	Selectors SelectorFlag

	EntryID  string
	ParentID string
	SpiffeID string
}

func (sc *ShowConfig) Validate() error {
	// If entryID is given, it should be the only constraint
	if sc.EntryID != "" {
		if sc.ParentID != "" || sc.SpiffeID != "" || len(sc.Selectors) > 0 {
			return errors.New("The -entryID flag can't be combined with others")
		}
	}

	return nil
}

type ShowCLI struct {
	Client registration.RegistrationClient
	Config *ShowConfig

	Entries []*common.RegistrationEntry
}

func (ShowCLI) Synopsis() string {
	return "Displays configured registration entries"
}

func (s ShowCLI) Help() string {
	_, err := s.newConfig([]string{"-h"})
	return err.Error()
}

func (s *ShowCLI) Run(args []string) int {
	// If an Entry ID was specified, look it up directly then exit
	if s.Config.EntryID != "" {
		err := fetchByEntryID(s.Config.EntryID)
		if err != nil {
			fmt.Printf("Error fetching entry ID %s: %s\n", s.Config.EntryID, err)
			return 1
		}

		s.printEntries()
		return 0
	}

	// If we didn't get any args, fetch everything then exit
	if s.Config.ParentID != "" && s.Config.SpiffeID != "" && len(s.Config.Selectors) == 0 {
		err := s.fetchAllEntries()
		if err != nil {
			fmt.Printf("Error fetching entries: %s\n", err)
			return 1
		}

		s.printEntries()
		return 0
	}

	// Fetch all records matching each constraint, then find and
	// print the intersection at the end.
	err := s.fetchByParentID()
	if err != nil {
		fmt.Printf("Error fetching by parent ID: %s", err)
		return 1
	}

	err := s.fetchBySpiffeID()
	if err != nil {
		fmt.Printf("Error fetching by SPIFFE ID: %s", err)
		return 1
	}

	err := s.fetchBySelectors()
	if err != nil {
		fmt.Printf("Error fetching by selectors: %s", err)
		return 1
	}

	s.filterEntries()
	s.printEntries()
	return 0
}

func (s *ShowCLI) fetchAllEntries() error {
	var err error
	s.Entries, err = s.Client.FetchEntries(context.TODO(), common.Empty{})
	return err
}

// fetchByEntryID uses the configured EntryID to fetch the appropriate registration entry
func (s *ShowCLI) fetchByEntryID(id string) error {
	regID := &registration.RegistrationEntryID{Id: id}
	entry, err := s.Client.FetchEntry(context.TODO(), regID)
	s.Entries = []*common.RegistrationEntry{entry}
	return err
}

// fetchByParentID appends registration entries which match the configured
// Parent ID to `entries`
func (s *ShowCLI) fetchByParentID() error {
	if s.Config.ParentID != "" {
		parentID := &registration.ParentID{Id: id}
		entries, err := s.Client.ListByParentID(context.TODO(), parentID)
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries.Entries...)
	}

	return nil
}

// fetchBySpiffeID appends registration entries which match the configured
// SPIFFE ID to `entries`
func (s *ShowCLI) fetchBySpiffeID() error {
	if s.Config.SpiffeID != "" {
		spiffeID := &registration.SpiffeID{Id: id}
		entries, err := s.Client.ListBySpiffeID(context.TODO(), spiffeID)
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries.Entries...)
	}

	return nil
}

// fetchBySelectors fetches all registration entries containing the full
// set of configured selectors, appending them to `entries`
func (s *ShowCLI) fetchBySelectors() error {
	for _, sel := range s.Config.Selectors {
		s, err := parseSelector(sel)
		if err != nil {
			return err
		}

		entries, err := s.Client.ListBySelector(context.TODO())
		if err != nil {
			return err
		}

		s.Entries = append(s.Entries, entries...)
	}

	return nil
}

func (s *ShowCLI) filterEntries() {
	// for i, e := range s.Entries {
	// 	if
	// }
}

func (s ShowCLI) printEntries(entries *common.RegistrationEntries) {
	msg := fmt.Sprintf("Found %v ", len(entries))
	msg = util.Pluralizer(msg, "entry", "entries", len(entries))

	fmt.Println(msg)
	for _, e := range entries {
		printEntry(e, "")
	}
}

func (s *ShowCLI) loadConfig(args []string) error {
	f := flag.NewFlagSet("entry show", flag.ContinueOnError)
	c := &ShowConfig{}

	f.StringVar(&c.Addr, "serverAddr", util.DefaultServerAddr, "Address of the SPIRE server")
	f.StringVar(&c.EntryID, "entryID", "", "The Entry ID of the records to show")
	f.StringVar(&c.ParentID, "parentID", "", "The Parent ID of the records to show")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID of the records to show")

	f.Var(&c.Selectors, "selector", "A colon-delimeted type:value selector. Can be used more than once")

	err := f.Parse(args)
	if err != nil {
		return c, err
	}

	s.Config = c
	s.Config.Client, err = util.NewRegistrationClient(c.Addr)
	return err
}
