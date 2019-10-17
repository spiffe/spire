package api

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/spire/api/workload"
)

type WatchConfig struct {
	socketPath string
}

type WatchCLI struct {
	config *WatchConfig

	stopChan chan struct{}
}

func (WatchCLI) Synopsis() string {
	return "Attaches to the Workload API and prints updates as they're received"
}

func (w WatchCLI) Help() string {
	err := w.parseConfig([]string{"-h"})
	return err.Error()
}

func (w *WatchCLI) Run(args []string) int {
	err := w.parseConfig(args)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	w.stopChan = make(chan struct{})
	client, errChan := w.startClient()

	updateTime := time.Now()
	go w.signalListener()
	for {
		select {
		case <-w.stopChan:
			client.Stop()
			return 0
		case err := <-errChan:
			fmt.Fprintln(os.Stderr, err)
			return 1
		case u := <-client.UpdateChan():
			svids, err := parseAndValidateX509SVIDResponse(u)
			if err == nil {
				printX509SVIDResponse(svids, time.Since(updateTime))
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
			updateTime = time.Now()
		}
	}
}

func (w *WatchCLI) parseConfig(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	c := &WatchConfig{}
	fs.StringVar(&c.socketPath, "socketPath", "/tmp/agent.sock", "Path to the Workload API socket")

	w.config = c
	return fs.Parse(args)
}

func (w *WatchCLI) startClient() (workload.X509Client, chan error) {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: w.config.socketPath,
	}

	l := log.New(os.Stdout, "", log.LstdFlags)

	c := &workload.X509ClientConfig{
		Addr: addr,
		Log:  l,
	}

	client := workload.NewX509Client(c)
	errChan := make(chan error)
	go func() { errChan <- client.Start() }()

	return client, errChan
}

func (w *WatchCLI) signalListener() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	close(w.stopChan)
}
