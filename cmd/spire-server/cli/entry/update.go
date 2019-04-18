package entry

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"

	"golang.org/x/net/context"
)

type UpdateConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string

	// Path to an optional data file. If set, other
	// opts will be ignored.
	Path string

	// Registration entry id to update
	EntryID string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	Selectors StringsFlag

	ParentID   string
	SpiffeID   string
	Downstream bool
	TTL        int

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	FederatesWith StringsFlag

	// Whether or not the registration entry is for an "admin" workload
	Admin bool

	// Expiry of entry
	EntryExpiry int64

	// DNSNames entries for SVIDs based on this entry
	DNSNames StringsFlag
}

// Validate performs basic validation, even on fields that we
// have defaults defined for
func (rc *UpdateConfig) Validate() (err error) {
	if rc.RegistrationUDSPath == "" {
		return errors.New("a socket path for registration api is required")
	}

	// If a path is set, we have all we need
	if rc.Path != "" {
		return nil
	}

	if rc.EntryID == "" {
		return errors.New("entry ID is required")
	}

	if len(rc.Selectors) < 1 {
		return errors.New("at least one selector is required")
	}

	if rc.ParentID == "" {
		return errors.New("a parent ID is required")
	}

	if rc.SpiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	if rc.TTL < 0 {
		return errors.New("a TTL is required")
	}

	// make sure all SPIFFE ID's are well formed
	rc.SpiffeID, err = idutil.NormalizeSpiffeID(rc.SpiffeID, idutil.AllowAny())
	if err != nil {
		return err
	}
	rc.ParentID, err = idutil.NormalizeSpiffeID(rc.ParentID, idutil.AllowAny())
	if err != nil {
		return err
	}
	for i := range rc.FederatesWith {
		rc.FederatesWith[i], err = idutil.NormalizeSpiffeID(rc.FederatesWith[i], idutil.AllowAny())
		if err != nil {
			return err
		}
	}

	return nil
}

type UpdateCLI struct{}

func (UpdateCLI) Synopsis() string {
	return "Updates registration entries"
}

func (c UpdateCLI) Help() string {
	_, err := c.newConfig([]string{"-h"})
	return err.Error()
}

func (c UpdateCLI) Run(args []string) int {
	ctx := context.Background()

	config, err := c.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = config.Validate(); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	var entries []*common.RegistrationEntry
	if config.Path != "" {
		entries, err = c.parseFile(config.Path)
	} else {
		entries, err = c.parseConfig(config)
	}
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	cl, err := util.NewRegistrationClient(config.RegistrationUDSPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = c.registerEntries(ctx, cl, entries)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}

// parseConfig builds a registration entry from the given config
func (c UpdateCLI) parseConfig(config *UpdateConfig) ([]*common.RegistrationEntry, error) {
	e := &common.RegistrationEntry{
		EntryId:     config.EntryID,
		ParentId:    config.ParentID,
		SpiffeId:    config.SpiffeID,
		Ttl:         int32(config.TTL),
		Downstream:  config.Downstream,
		EntryExpiry: config.EntryExpiry,
		DnsNames:    config.DNSNames,
	}

	selectors := []*common.Selector{}
	for _, s := range config.Selectors {
		cs, err := parseSelector(s)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, cs)
	}

	e.Selectors = selectors
	e.FederatesWith = config.FederatesWith
	e.Admin = config.Admin
	return []*common.RegistrationEntry{e}, nil
}

func (UpdateCLI) parseFile(path string) ([]*common.RegistrationEntry, error) {
	entries := &common.RegistrationEntries{}

	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(dat, &entries); err != nil {
		return nil, err
	}
	return entries.Entries, nil
}

func (UpdateCLI) registerEntries(ctx context.Context, c registration.RegistrationClient, entries []*common.RegistrationEntry) error {
	for _, e := range entries {
		updated, err := c.UpdateEntry(ctx, &registration.UpdateEntryRequest{
			Entry: e,
		})
		if err != nil {
			fmt.Println("FAILED to update the following entry:")
			printEntry(e)
			return err
		}

		printEntry(updated)
	}

	return nil
}

func (UpdateCLI) newConfig(args []string) (*UpdateConfig, error) {
	f := flag.NewFlagSet("entry update", flag.ContinueOnError)
	c := &UpdateConfig{}

	f.StringVar(&c.EntryID, "entryID", "", "The Registration Entry ID of the record to update")
	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	f.StringVar(&c.ParentID, "parentID", "", "The SPIFFE ID of this record's parent")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID that this record represents")
	f.IntVar(&c.TTL, "ttl", 3600, "The lifetime, in seconds, for SVIDs issued based on this registration entry")

	f.StringVar(&c.Path, "data", "", "Path to a file containing registration JSON (optional)")

	f.Var(&c.Selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.FederatesWith, "federatesWith", "SPIFFE ID of a trust domain to federate with. Can be used more than once")

	f.BoolVar(&c.Admin, "admin", false, "If true, the SPIFFE ID in this entry will be granted access to the Registration API")
	f.BoolVar(&c.Downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")

	f.Int64Var(&c.EntryExpiry, "entryExpiry", 0, "An expiry, from epoch in seconds, for the resulting registration entry to be pruned")

	f.Var(&c.DNSNames, "dns", "A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once")

	return c, f.Parse(args)
}
