package main

import (
	"context"
	"flag"
	"fmt"
	"os/exec"
	"sync"

	"google.golang.org/grpc"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

type CreateUsers struct {
}

//Help prints the cmd usage
func (*CreateUsers) Help() string {
	return "Usage"
}

//Run create users
func (*CreateUsers) Run(args []string) int {
	ctx := context.Background()

	var users, ttl int
	var token string
	flags := flag.NewFlagSet("createusers", flag.ContinueOnError)
	flags.IntVar(&users, "workloads", 5, "Number of workloads to run in parallel")
	flags.StringVar(&token, "token", "", "Join token used in server and agent")
	flags.IntVar(&ttl, "ttl", 120, "SVID TTL")

	err := flags.Parse(args)
	if token == "" {
		return 1
	}

	c, err := newRegistrationClient(serverAddr)
	if err != nil {
		panic(err)
	}

	// Create users
	for i := 0; i < users; i++ {
		uid := 1000 + i

		fmt.Printf("Creating user %d\n", uid)

		// Create user
		o, err := exec.Command("bash", "-c", fmt.Sprintf("useradd --uid %d user%d", uid, uid)).CombinedOutput()
		if err != nil {
			fmt.Println(string(o))
			panic(err)
		}
	}

	var wg sync.WaitGroup

	// Register workloads
	for i := 0; i < users; i++ {
		uid := 1000 + i

		wg.Add(1)
		go func(uid int) {
			defer wg.Done()

			// Register workload
			parentID := parentSpiffeIDPrefix + token
			selectorValue := fmt.Sprintf("uid:%d", uid)
			spiffeID := spiffeIDPrefix + fmt.Sprintf("uid%d", uid)
			fmt.Printf("Parent ID: %s\nSelector Value: %s\nSpiffe ID: %s\n", parentID, selectorValue, spiffeID)
			entry := &common.RegistrationEntry{
				ParentId: parentID,
				Selectors: []*common.Selector{
					&common.Selector{
						Type:  "unix",
						Value: selectorValue,
					},
				},
				SpiffeId: spiffeID,
				Ttl:      int32(ttl),
			}
			entryID, err := c.CreateEntry(ctx, entry)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Created entry ID %s\n", entryID.Id)
		}(uid)
	}

	wg.Wait()

	return 0
}

//Synopsis of the command
func (*CreateUsers) Synopsis() string {
	return "Runs the server"
}

func newRegistrationClient(address string) (registration.RegistrationClient, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}
