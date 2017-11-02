package command

import (
	"context"
	"flag"
	"fmt"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"os"
	"time"
)

type FetchSvidConfig struct {
	socketPath string
}

// Perform basic validation, even on fields that we
// have defaults defined for
func (rc *FetchSvidConfig) Validate() error {
	return nil
}

type FetchSvid struct {
	WorkloadClient workload.WorkloadClient
}

func (FetchSvid) Synopsis() string {
	return "Fetches an SVID from Workload API"
}

func (f FetchSvid) Help() string {
	_, err := f.newConfig([]string{"-h"})
	return err.Error()
}

func (f FetchSvid) Run(args []string) int {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	config, err := f.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = config.Validate(); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = f.grpcUDSClient(config.socketPath)
	err = f.dumpBundles(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}

func (f *FetchSvid) dumpBundles(ctx context.Context) (err error) {
	bundles, err := f.WorkloadClient.FetchAllBundles(ctx, &workload.Empty{})
	if err != nil {
		return
	}

	if len(bundles.Bundles) == 0 {
		log("Fetched zero bundles. Make sure this Workload is registered")
		return
	}

	log("Writing %d bundles!\n", len(bundles.Bundles))
	for index, bundle := range bundles.Bundles {
		log("Writing private key #%d...\n", index+1)

		filename := fmt.Sprintf("%d.key", index)
		err = ioutil.WriteFile(filename, bundle.SvidPrivateKey, os.ModePerm)
		if err != nil {
			return
		}

		log("Writing SVID #%d...\n", index+1)

		filename = fmt.Sprintf("%d.svid", index)
		err = ioutil.WriteFile(filename, bundle.Svid, os.ModePerm)
		if err != nil {
			return
		}

		log("Writing CA #%d...\n", index+1)

		filename = fmt.Sprintf("%d.ca", index)
		err = ioutil.WriteFile(filename, bundle.SvidBundle, os.ModePerm)
		if err != nil {
			return
		}
	}

	log("TTL is #%d seconds...\n", bundles.Ttl)

	return
}

func (FetchSvid) newConfig(args []string) (*FetchSvidConfig, error) {
	f := flag.NewFlagSet("fetchsvid", flag.ContinueOnError)
	c := &FetchSvidConfig{}
	f.StringVar(&c.socketPath, "socketPath", "/tmp/agent.sock", "Workload API uds Path")

	return c, f.Parse(args)
}

func (f *FetchSvid) grpcUDSClient(socketPath string) (err error) {
	conn, err := grpc.Dial(socketPath,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))

	f.WorkloadClient = workload.NewWorkloadClient(conn)
	return
}

func log(format string, a ...interface{}) {
	fmt.Print(time.Now().Format(time.Stamp), ": ")
	fmt.Printf(format, a...)
}
