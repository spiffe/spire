package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"

	"golang.org/x/net/context"
)

type DeleteConfig struct {
	// Address of SPIRE server
	Addr string

	// ID of the record to delete
	EntryID string
}

// Perform basic validation
func (dc *DeleteConfig) Validate() error {
	if dc.Addr == "" {
		return errors.New("a server address is required")
	}

	if dc.EntryID == "" {
		return errors.New("an entry ID is required")
	}

	return nil
}

type DeleteCLI struct{}

func (DeleteCLI) Synopsis() string {
	return "Deletes registration entries"
}

func (d DeleteCLI) Help() string {
	_, err := d.newConfig([]string{"-h"})
	return err.Error()
}

func (d DeleteCLI) Run(args []string) int {
	config, err := d.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = config.Validate(); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	cl, err := util.NewRegistrationClient(config.Addr)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	req := &registration.RegistrationEntryID{
		Id: config.EntryID,
	}
	e, err := cl.DeleteEntry(context.TODO(), req)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Printf("Deleted the following entry:\n\n")
	printEntry(e, config.EntryID)
	return 0
}

func (DeleteCLI) newConfig(args []string) (*DeleteConfig, error) {
	f := flag.NewFlagSet("entry delete", flag.ContinueOnError)
	c := &DeleteConfig{}

	f.StringVar(&c.Addr, "serverAddr", util.DefaultServerAddr, "Address of the SPIRE server")
	f.StringVar(&c.EntryID, "entryID", "", "The Registration Entry ID of the record to delete")

	return c, f.Parse(args)
}
