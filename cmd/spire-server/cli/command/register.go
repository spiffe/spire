package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"
)

type RegisterConfig struct {
	// Address of SPIRE server
	Addr string

	// Path to an optional data file. If set, other
	// opts will be ignored.
	Path string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	Selectors SelectorFlag

	ParentID string
	SpiffeID string
	Ttl      int
}

// Perform basic validation, even on fields that we
// have defaults defined for
func (rc *RegisterConfig) Validate() error {
	if rc.Addr == "" {
		return errors.New("a server address is required")
	}

	// If a path is set, we have all we need
	if rc.Path != "" {
		return nil
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

	if rc.Ttl < 0 {
		return errors.New("a TTL is required")
	}

	return nil
}

type Register struct{}

func (Register) Synopsis() string {
	return "Creates registration entries"
}

func (r Register) Help() string {
	_, err := r.newConfig([]string{"-h"})
	return err.Error()
}

func (r Register) Run(args []string) int {
	config, err := r.newConfig(args)
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
		entries, err = r.parseFile(config.Path)
	} else {
		entries, err = r.parseConfig(config)
	}
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c, err := newRegistrationClient(config.Addr)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = r.registerEntries(c, entries)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}

// parseConfig builds a registration entry from the given config
func (r Register) parseConfig(c *RegisterConfig) ([]*common.RegistrationEntry, error) {
	e := &common.RegistrationEntry{
		ParentId: c.ParentID,
		SpiffeId: c.SpiffeID,
		Ttl:      int32(c.Ttl),
	}

	selectors := []*common.Selector{}
	for _, s := range c.Selectors {
		cs, err := r.parseSelector(s)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, cs)
	}

	e.Selectors = selectors
	return []*common.RegistrationEntry{e}, nil
}

func (Register) parseFile(path string) ([]*common.RegistrationEntry, error) {
	entries := &common.RegistrationEntries{}

	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(dat, &entries)
	return entries.Entries, nil
}

// parseSelector parses a CLI string from type:value into a selector type.
// Everything to the right of the first ":" is considered a selector value.
func (Register) parseSelector(str string) (*common.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &common.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}

func (r Register) registerEntries(c registration.RegistrationClient, entries []*common.RegistrationEntry) error {
	for _, e := range entries {
		id, err := c.CreateEntry(context.TODO(), e)
		if err != nil {
			fmt.Println("FAILED to create the following entry:")
			r.printEntry(e, "")
			return err
		}

		r.printEntry(e, id.Id)
	}

	return nil
}

func (Register) printEntry(e *common.RegistrationEntry, id string) {
	if id != "" {
		fmt.Printf("Entry ID:\t%s\n", id)
	}
	fmt.Printf("SPIFFE ID:\t%s\n", e.SpiffeId)
	fmt.Printf("Parent ID:\t%s\n", e.ParentId)
	fmt.Printf("TTL:\t\t%v\n", e.Ttl)

	for _, s := range e.Selectors {
		fmt.Printf("Selector:\t%s:%s\n", s.Type, s.Value)
	}

	fmt.Println()
}

func (Register) newConfig(args []string) (*RegisterConfig, error) {
	f := flag.NewFlagSet("register", flag.ContinueOnError)
	c := &RegisterConfig{}

	f.StringVar(&c.Addr, "serverAddr", defaultServerAddr, "Address of the SPIRE server")
	f.StringVar(&c.ParentID, "parentID", "", "The SPIFFE ID of this record's parent")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID that this record represents")
	f.IntVar(&c.Ttl, "ttl", 3600, "A TTL, in seconds, for any SVID issued as a result of this record")

	f.StringVar(&c.Path, "data", "", "Path to a file containing registration JSON (optional)")

	f.Var(&c.Selectors, "selector", "A colon-delimeted type:value selector. Can be used more than once")

	return c, f.Parse(args)
}

// Define a custom type for selectors. Doing
// this allows us to support repeatable flags
type SelectorFlag []string

func (s *SelectorFlag) String() string {
	return fmt.Sprint(*s)
}

func (s *SelectorFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
