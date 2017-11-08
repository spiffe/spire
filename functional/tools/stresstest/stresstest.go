package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	serverAddr           = "localhost:8081"
	parentSpiffeIDPrefix = "spiffe://example.org/spire/agent/join_token/"
	spiffeIDPrefix       = "spiffe://example.org/"
	workloadPath         = "/spire/functional/tools/workload/workload"
)

func main() {
	token := flag.String("token", "", "Join token used in server and agent")
	users := flag.Int("workloads", 5, "Number of workloads to run in parallel")
	timeout := flag.Int("timeout", 15, "Total time to run test")
	ttl := flag.Int("ttl", 120, "SVID TTL")
	flag.Parse()

	if *token == "" {
		flag.Usage()
		return
	}

	c, err := newRegistrationClient(serverAddr)
	if err != nil {
		panic(err)
	}

	// Create users and register workloads
	for i := 0; i < *users; i++ {
		uid := 1000 + i

		fmt.Printf("Creating user %d\n", uid)

		// Create user
		o, err := exec.Command("bash", "-c", fmt.Sprintf("useradd --uid %d user%d", uid, uid)).CombinedOutput() //adduser --uid 1111 --disabled-password --shell /bin/bash --ingroup spire spire
		if err != nil {
			fmt.Println(string(o))
			panic(err)
		}

		// Register workload
		parentID := parentSpiffeIDPrefix + *token
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
			Ttl:      int32(*ttl),
		}
		entryID, err := c.CreateEntry(context.TODO(), entry)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Created entry ID %s\n", entryID.Id)
	}

	time.Sleep(time.Second * time.Duration(10))

	var wg sync.WaitGroup
	wg.Add(*users)

	// Launch workloads
	for i := 0; i < *users; i++ {
		uid := 1000 + i

		fmt.Printf("Launching workload %d\n", uid)

		c := exec.Command(workloadPath, "-timeout", strconv.Itoa(*timeout))
		c.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid)},
		}
		go func() {
			defer wg.Done()
			o, err := c.CombinedOutput()
			if err != nil {
				panic(err)
			}
			fmt.Printf("Workload %d finished: %s\n", uid, string(o))
		}()
	}
	fmt.Printf("Waiting for workloads to finish...\n")

	wg.Wait()

	fmt.Printf("Finished\n")
}

func newRegistrationClient(address string) (registration.RegistrationClient, error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	return registration.NewRegistrationClient(conn), err
}
