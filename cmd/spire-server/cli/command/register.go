package command

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"

	"golang.org/x/net/context"

	"log"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

type RegisterCommand struct {
	Client registration.RegistrationClient
}

func (*RegisterCommand) Help() string {
	return "Usage: spire-server register <data-file>"
}

func (c *RegisterCommand) Run(args []string) int {
	var err error

	// TODO: Make address configurable
	if c.Client == nil {
		c.Client, err = newRegistrationClient(defaultServerAddr)
		if err != nil {
			log.Fatalf("Failed: %v", err)
			return -1
		}
	}

	// Get filename
	if len(args) != 1 {
		log.Fatalf("Exactly one argument expected but got %d", len(args))
		return -1
	}
	dataFile := args[0]
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		log.Fatalf("File not found: %s", dataFile)
		return -1
	}

	// Load entries from data file
	entries := &common.RegistrationEntries{}
	dat, err := ioutil.ReadFile(dataFile)
	if err != nil {
		log.Fatalf("Failed: %v", err)
		return -1
	}

	json.Unmarshal(dat, &entries)

	// Inject each entry and verify it
	for index, registeredEntry := range entries.Entries {
		log.Printf("Creating entry #%d...\n", index+1)
		entityID, err := c.createEntry(registeredEntry)
		if err != nil {
			log.Fatalf("Failed: %v", err)
			return -1
		}
		valid, err := c.validateEntry(entityID, registeredEntry)
		if err != nil {
			log.Fatalf("Failed: %v", err)
			return -1
		}
		if valid {
			log.Printf("Fetched entity %s is OK!\n\n", entityID)
		} else {
			log.Printf("Fetched entity %s mismatch! Aborting...\n", entityID)
			return -1
		}
	}

	log.Printf("Registration OK!\n")

	return 0
}

func (*RegisterCommand) Synopsis() string {
	return "Registers data in server"
}

func (c *RegisterCommand) createEntry(registeredEntry *common.RegistrationEntry) (string, error) {
	result, err := c.Client.CreateEntry(context.Background(), registeredEntry)
	if err != nil {
		return "", err
	}
	return result.Id, nil
}

func (c *RegisterCommand) validateEntry(entityID string, registeredEntry *common.RegistrationEntry) (ok bool, err error) {
	registrationEntryID := &registration.RegistrationEntryID{Id: entityID}
	fetchedRegisteredEntry, err := c.Client.FetchEntry(context.Background(), registrationEntryID)
	if err != nil {
		return
	}

	ok = reflect.DeepEqual(fetchedRegisteredEntry, registeredEntry)

	return
}
