package command

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"log"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

const (
	apiAddress = "localhost:8081" // TODO: Make address configurable
)

type RegisterCommand struct {
	Client registration.RegistrationClient
}

func (*RegisterCommand) Help() string {
	return "Usage: spire-server register <data-file>"
}

func (c *RegisterCommand) Run(args []string) int {
	if c.Client == nil {
		err := c.initializeGrpcClient(apiAddress)
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

func (c *RegisterCommand) initializeGrpcClient(address string) (err error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	c.Client = registration.NewRegistrationClient(conn)

	return
}
