package command

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"

	"log"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

const (
	entryURL = "http://localhost:8080/entry" // TODO: Make address configurable
)

type RegisterCommand struct {
}

func (*RegisterCommand) Help() string {
	return "Usage: spire-server register <data-file>"
}

func (*RegisterCommand) Run(args []string) int {
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
		entityID, err := createEntry(registeredEntry)
		if err != nil {
			log.Fatalf("Failed: %v", err)
			return -1
		}
		valid, err := validateEntry(entityID, registeredEntry)
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

func createEntry(registeredEntry *common.RegistrationEntry) (entityID string, err error) {
	reqStr, err := json.Marshal(registeredEntry)
	if err != nil {
		return
	}
	log.Printf("Invoking CreateEntry: %s\n", string(reqStr))

	req, err := http.NewRequest("POST", entryURL, bytes.NewBuffer(reqStr))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respStr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	log.Printf("CreateEntry returned: %s\n", string(respStr))

	registeredEntryID := &registration.RegistrationEntryID{}
	err = json.Unmarshal([]byte(respStr), &registeredEntryID)
	if err != nil {
		return
	}
	entityID = registeredEntryID.Id

	return
}

func validateEntry(entityID string, registeredEntry *common.RegistrationEntry) (ok bool, err error) {
	log.Printf("Invoking FetchEntry: %s\n", entityID)

	req, err := http.NewRequest("GET", entryURL+"/"+entityID, bytes.NewBufferString(""))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respStr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	log.Printf("FetchEntry returned: %s\n", string(respStr))

	var fetchedRegisteredEntry *common.RegistrationEntry
	err = json.Unmarshal([]byte(respStr), &fetchedRegisteredEntry)
	if err != nil {
		return
	}

	ok = reflect.DeepEqual(fetchedRegisteredEntry, registeredEntry)

	return
}
