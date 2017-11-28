package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
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
	workloadPath         = "/go/src/github.com/spiffe/spire/functional/tools/workload/workload"
)

type workloadStats struct {
	uid     int
	runtime time.Duration
	output  string
	success bool
}

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

	if _, err := os.Stat(workloadPath); os.IsNotExist(err) {
		panic("Do not run this tool outside the Docker container")
	}

	c, err := newRegistrationClient(serverAddr)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup

	// Create users
	for i := 0; i < *users; i++ {
		uid := 1000 + i

		fmt.Printf("Creating user %d\n", uid)

		// Create user
		o, err := exec.Command("bash", "-c", fmt.Sprintf("useradd --uid %d user%d", uid, uid)).CombinedOutput()
		if err != nil {
			fmt.Println(string(o))
			panic(err)
		}
	}

	// Register workloads
	for i := 0; i < *users; i++ {
		uid := 1000 + i

		wg.Add(1)
		go func(uid int) {
			defer wg.Done()

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
		}(uid)
	}

	wg.Wait()
	fmt.Printf("Waiting for entries to be propagated...\n")
	time.Sleep(time.Second * time.Duration(60))

	statch := make(chan *workloadStats, *users)

	// Launch workloads
	for i := 0; i < *users; i++ {
		uid := 1000 + i

		fmt.Printf("Launching workload %d\n", uid)

		c := exec.Command(workloadPath, "-timeout", strconv.Itoa(*timeout))
		c.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid)},
		}
		wg.Add(1)
		go func(uid int) {
			started := time.Now()
			defer wg.Done()

			o, err := c.CombinedOutput()
			if err != nil {
				fmt.Printf("%d failed...\n", uid)
			}
			statch <- &workloadStats{
				uid:     uid,
				success: err == nil,
				output:  string(o),
				runtime: time.Now().Sub(started),
			}
		}(uid)
	}
	fmt.Printf("Waiting for workloads to finish... Test time is %d seconds\n", *timeout)

	wg.Wait()

	fmt.Printf("Finished. Summary:\n")

	// Print stats
	statusMap := map[bool]string{true: "success", false: "failed"}
	for i := 0; i < *users; i++ {
		s := <-statch
		logfile := fmt.Sprintf("%d.log", s.uid)
		fmt.Printf("Workload %d: status: %s, runtime: %s, logfile: %s\n",
			s.uid,
			statusMap[s.success],
			s.runtime.String(),
			logfile)

		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to open/create %s: %s\n", logfile, err)
		} else {
			defer f.Close()
			f.WriteString(s.output)
		}
	}
}

func newRegistrationClient(address string) (registration.RegistrationClient, error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	return registration.NewRegistrationClient(conn), err
}
