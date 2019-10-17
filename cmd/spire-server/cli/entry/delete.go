package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/spire/api/registration"

	"golang.org/x/net/context"
)

type DeleteConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string

	// ID of the record to delete
	EntryID string
}

// Perform basic validation
func (dc *DeleteConfig) Validate() error {
	if dc.RegistrationUDSPath == "" {
		return errors.New("a socket path for registration api is required")
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
	ctx := context.Background()

	config, err := d.newConfig(args)
	if err != nil {
		return d.printErr(err)
	}

	if err = config.Validate(); err != nil {
		return d.printErr(err)
	}

	cl, err := util.NewRegistrationClient(config.RegistrationUDSPath)
	if err != nil {
		return d.printErr(err)
	}

	req := &registration.RegistrationEntryID{
		Id: config.EntryID,
	}
	e, err := cl.DeleteEntry(ctx, req)
	if err != nil {
		return d.printErr(err)
	}

	fmt.Printf("Deleted the following entry:\n\n")
	printEntry(e)
	return 0
}

func (DeleteCLI) newConfig(args []string) (*DeleteConfig, error) {
	f := flag.NewFlagSet("entry delete", flag.ContinueOnError)
	c := &DeleteConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	f.StringVar(&c.EntryID, "entryID", "", "The Registration Entry ID of the record to delete")

	return c, f.Parse(args)
}

func (DeleteCLI) printErr(err error) int {
	fmt.Println(err.Error())
	return 1
}
