package entry

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"google.golang.org/grpc/codes"

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

	srvCl, err := util.NewServerClient(config.RegistrationUDSPath)
	if err != nil {
		return d.printErr(err)
	}
	defer srvCl.Release()
	cl := srvCl.NewEntryClient()

	req := &entry.BatchDeleteEntryRequest{
		Ids: []string{config.EntryID},
	}
	resp, err := cl.BatchDeleteEntry(ctx, req)
	if err != nil {
		return d.printErr(err)
	}

	sts := resp.Results[0].Status
	switch sts.Code {
	case int32(codes.OK):
		fmt.Printf("Deleted entry with ID: %s\n", config.EntryID)
		return 0
	default:
		return d.printErr(fmt.Errorf("failed to delete entry: %s", sts.Message))
	}
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
