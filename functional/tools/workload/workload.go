package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	workload "github.com/spiffe/spire/proto/spire/api/workload"
	"google.golang.org/grpc/metadata"
)

// Workload is the component that consumes Workload API and renews certs
type Workload struct {
	workloadClient        workload.SpiffeWorkloadAPIClient
	workloadClientContext context.Context
	timeout               int
}

// NewWorkload creates a new workload
func NewWorkload(workloadClientContext context.Context, workloadClient workload.SpiffeWorkloadAPIClient, timeout int) *Workload {
	return &Workload{
		workloadClientContext: workloadClientContext,
		workloadClient:        workloadClient,
		timeout:               timeout,
	}
}

// RunDaemon starts the main loop
// TODO: consume go-spiffe
func (w *Workload) RunDaemon(ctx context.Context) error {
	// Create channel for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Create timer for timeout
	timeoutTimer := time.NewTimer(time.Second * time.Duration(w.timeout))
	defer timeoutTimer.Stop()

	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx = metadata.NewOutgoingContext(ctx, header)

	stream, err := w.workloadClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return err
	}

	// Main loop
	for {
		respChan := make(chan *workload.X509SVIDResponse)
		errChan := make(chan error)
		go func() {
			resp, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}

			respChan <- resp
			return
		}()

		select {
		case resp := <-respChan:
			err = w.validate(resp)
			if err != nil {
				return err
			}
		case err := <-errChan:
			return err
		case <-timeoutTimer.C:
			log("Global timeout! Will exit.\n")
			return nil
		case <-interrupt:
			log("Interrupted! Will exit.\n")
			return nil
		}
	}
}

func (w *Workload) validate(resp *workload.X509SVIDResponse) error {
	if len(resp.Svids) == 0 {
		return errors.New("Fetched zero bundles")
	}

	for _, svid := range resp.Svids {
		certs, err := x509.ParseCertificates(svid.X509Svid)
		if err != nil {
			return err
		}
		leaf := certs[0]
		intermediates := certs[1:]

		bundle, err := x509.ParseCertificates(svid.Bundle)
		if err != nil {
			return err
		}

		rootPool := x509.NewCertPool()
		for _, c := range bundle {
			rootPool.AddCert(c)
		}

		intermediatePool := x509.NewCertPool()
		for _, c := range intermediates {
			intermediatePool.AddCert(c)
		}

		verifyOpts := x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediatePool,
		}

		_, err = leaf.Verify(verifyOpts)
		if err != nil {
			return err
		}
	}

	return nil
}

func log(format string, a ...interface{}) {
	fmt.Print(time.Now().Format(time.Stamp), ": ")
	fmt.Printf(format, a...)
}
