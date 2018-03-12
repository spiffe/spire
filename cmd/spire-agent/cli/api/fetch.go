package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"time"

	"github.com/spiffe/spire/proto/api/workload"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type FetchConfig struct {
	silent     bool
	socketPath string
	timeout    int
	writePath  string
}

type FetchCLI struct {
	config *FetchConfig
}

func (FetchCLI) Synopsis() string {
	return "Fetches SVIDs from the Workload API"
}

func (f FetchCLI) Help() string {
	err := f.parseConfig([]string{"-h"})
	return err.Error()
}

func (f *FetchCLI) Run(args []string) int {
	err := f.parseConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	client, err := f.dial()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	start := time.Now()
	resp, err := f.fetchX509SVID(client)
	respTime := time.Now().Sub(start)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if !f.config.silent {
		f.printResponse(resp, respTime)
	}

	if f.config.writePath != "" {
		err = f.writeResponse(resp)
		if err != nil {
			fmt.Println(err.Error())
			return 1
		}
	}

	return 0
}

func (f *FetchCLI) parseConfig(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	c := &FetchConfig{}
	fs.BoolVar(&c.silent, "silent", false, "Suppress stdout")
	fs.IntVar(&c.timeout, "timeout", 1, "Number of seconds to wait for a response")
	fs.StringVar(&c.socketPath, "socketPath", "/tmp/agent.sock", "Path to the Workload API socket")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional)")

	f.config = c
	return fs.Parse(args)
}

func (f *FetchCLI) fetchX509SVID(c workload.SpiffeWorkloadAPIClient) (*workload.X509SVIDResponse, error) {
	timeout := time.Duration(f.config.timeout) * time.Second
	header := metadata.Pairs("workload.spiffe.io", "true")

	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, header)
	ctx, _ = context.WithTimeout(ctx, timeout)

	stream, err := c.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	return stream.Recv()
}

func (f FetchCLI) printResponse(resp *workload.X509SVIDResponse, respTime time.Duration) {
	lenMsg := fmt.Sprintf("Fetched %v bundle", len(resp.Svids))
	if len(resp.Svids) != 1 {
		lenMsg = lenMsg + "s"
	}
	lenMsg = lenMsg + fmt.Sprintf(" in %s", respTime)

	fmt.Println(lenMsg)
	for _, s := range resp.Svids {
		fmt.Println()
		f.printSVID(s)
	}

	fmt.Println()
}

func (f FetchCLI) printSVID(msg *workload.X509SVID) {
	// Print SPIFFE ID first so if we run into a problem, we
	// get to know which record it was
	fmt.Printf("SPIFFE ID:\t\t%s\n", msg.SpiffeId)

	// Parse SVID and CA bundle. If we encounter an error,
	// simply print it and return so we can go to the next bundle
	svid, err := x509.ParseCertificate(msg.X509Svid)
	if err != nil {
		fmt.Printf("ERROR: Could not parse SVID: %s\n", err)
		return
	}

	svidBundle, err := x509.ParseCertificates(msg.Bundle)
	if err != nil {
		fmt.Printf("ERROR: Could not parse CA Certificates: %s\n", err)
		return
	}

	fmt.Printf("SVID Valid After:\t%v\n", svid.NotBefore)
	fmt.Printf("SVID Valid Until:\t%v\n", svid.NotAfter)
	for i, ca := range svidBundle {
		num := i + 1
		fmt.Printf("CA #%v Valid After:\t%v\n", num, ca.NotBefore)
		fmt.Printf("CA #%v Valid Until:\t%v\n", num, ca.NotAfter)
	}
}

func (f FetchCLI) writeResponse(resp *workload.X509SVIDResponse) error {
	for i, svid := range resp.Svids {
		svidName := fmt.Sprintf("svid.%v.pem", i)
		keyName := fmt.Sprintf("svid.%v.key", i)
		bundleName := fmt.Sprintf("bundle.%v.pem", i)

		err := f.writeCerts(svidName, svid.X509Svid)
		if err != nil {
			return err
		}

		err = f.writeKey(keyName, svid.X509SvidKey)
		if err != nil {
			return err
		}

		err = f.writeCerts(bundleName, svid.Bundle)
		if err != nil {
			return err
		}
	}

	return nil
}

// writeCerts takes a slice of data, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to filename
func (f FetchCLI) writeCerts(filename string, data []byte) error {
	// TODO: Is there a better way to do this?
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return err
	}

	pemData := []byte{}
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return f.writeFile(filename, pemData)
}

// writeKey takes a private key, formats as PEM, and writes it to filename
func (f FetchCLI) writeKey(filename string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	return f.writeFile(filename, pem.EncodeToMemory(b))
}

// writeFile creates or truncates filename, and writes data to it
func (f FetchCLI) writeFile(filename string, data []byte) error {
	p := path.Join(f.config.writePath, filename)
	return ioutil.WriteFile(p, data, os.ModePerm)
}

func (f FetchCLI) dial() (workload.SpiffeWorkloadAPIClient, error) {
	// Workload API is unauthenticated
	conn, err := grpc.Dial(f.config.socketPath, grpc.WithInsecure(), grpc.WithDialer(f.dialer))
	if err != nil {
		return nil, err
	}

	return workload.NewSpiffeWorkloadAPIClient(conn), nil
}

// dialer gets passed to grpc and serves as the mechanism for
// calling a unix domain socket.
// TODO: is there a better way to do this?
func (f FetchCLI) dialer(addr string, timeout time.Duration) (net.Conn, error) {
	// Assume we're only dialing sockets
	return net.DialTimeout("unix", addr, timeout)
}
