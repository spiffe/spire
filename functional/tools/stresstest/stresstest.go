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

	fmt.Printf("Waiting for entries to be propagated...\n")
	time.Sleep(time.Second * time.Duration(10))

	stats := make(map[int]*workloadStats)

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
		go func(uid int) {
			s := &workloadStats{}
			started := time.Now()
			defer wg.Done()

			o, err := c.CombinedOutput()

			s.success = err == nil
			s.output = string(o)
			s.runtime = time.Now().Sub(started)

			stats[uid] = s
		}(uid)
	}
	fmt.Printf("Waiting for workloads to finish... Test time is %d seconds\n", *timeout)

	wg.Wait()

	fmt.Printf("Finished. Summary:\n")

	statusMap := map[bool]string{true: "success", false: "failed"}
	for k, v := range stats {
		logfile := fmt.Sprintf("%d.log", k)
		fmt.Printf("Workload %d: status: %s, runtime: %s, logfile: %s\n",
			k,
			statusMap[v.success],
			v.runtime.String(),
			logfile)

		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to open/create %s: %s\n", logfile, err)
		} else {
			defer f.Close()
			f.WriteString(v.output)
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
