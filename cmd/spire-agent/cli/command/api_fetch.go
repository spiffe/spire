package command

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
	"strings"
	"time"

	"github.com/spiffe/spire/proto/api/workload"

	"google.golang.org/grpc"
)

type APIFetchConfig struct {
	silent     bool
	socketPath string
	spiffeID   string
	writePath  string
}

type APIFetch struct {
	config *APIFetchConfig
}

func (APIFetch) Synopsis() string {
	return "Fetches SVIDs from the Workload API"
}

func (f APIFetch) Help() string {
	err := f.parseConfig([]string{"-h"})
	return err.Error()
}

func (f *APIFetch) Run(args []string) int {
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
	bundles, err := f.fetchBundles(context.TODO(), client)
	respTime := time.Now().Sub(start)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if !f.config.silent {
		f.printBundles(bundles, respTime)
	}

	if f.config.writePath != "" {
		err = f.writeBundles(bundles)
		if err != nil {
			fmt.Println(err.Error())
			return 1
		}
	}

	return 0
}

func (f *APIFetch) parseConfig(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	c := &APIFetchConfig{}
	fs.BoolVar(&c.silent, "silent", false, "Suppress stdout")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "Retrieve only a specific SPIFFE ID (optional)")
	fs.StringVar(&c.socketPath, "socketPath", "/tmp/agent.sock", "Path to the Workload API socket")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional)")

	f.config = c
	return fs.Parse(args)
}

func (f *APIFetch) fetchBundles(ctx context.Context, c workload.WorkloadClient) (*workload.Bundles, error) {
	var resp *workload.Bundles
	var err error

	if f.config.spiffeID == "" {
		resp, err = c.FetchAllBundles(ctx, &workload.Empty{})
	} else {
		id := &workload.SpiffeID{Id: f.config.spiffeID}
		resp, err = c.FetchBundles(ctx, id)
	}

	if err != nil {
		return &workload.Bundles{}, err
	}

	return resp, nil
}

func (f APIFetch) printBundles(bundles *workload.Bundles, respTime time.Duration) {
	lenMsg := fmt.Sprintf("Fetched %v bundle", len(bundles.Bundles))
	if len(bundles.Bundles) != 1 {
		lenMsg = lenMsg + "s"
	}
	lenMsg = lenMsg + fmt.Sprintf(" in %s", respTime)

	ttlMsg := fmt.Sprintf("Check back in %v second", bundles.Ttl)
	if bundles.Ttl != 1 {
		ttlMsg = ttlMsg + "s"
	}

	fmt.Println(lenMsg)
	fmt.Println(ttlMsg)
	for _, b := range bundles.Bundles {
		fmt.Println()
		f.printBundle(b)
	}

	fmt.Println()
}

func (f APIFetch) printBundle(bundle *workload.WorkloadEntry) {
	// Print SPIFFE ID first so if we run into a problem, we
	// get to know which record it was
	fmt.Printf("SPIFFE ID:\t\t%s\n", bundle.SpiffeId)

	// Parse SVID and CA bundle. If we encounter an error,
	// simply print it and return so we can go to the next bundle
	svid, err := x509.ParseCertificate(bundle.Svid)
	if err != nil {
		fmt.Printf("ERROR: Could not parse SVID: %s\n", err)
		return
	}

	svidBundle, err := x509.ParseCertificates(bundle.SvidBundle)
	if err != nil {
		fmt.Printf("ERROR: Could not parse CA Certificates: %s\n", err)
		return
	}

	var federatedBundleIDs []string
	for id := range bundle.FederatedBundles {
		federatedBundleIDs = append(federatedBundleIDs, id)
	}

	fmt.Printf("SVID Valid After:\t%v\n", svid.NotBefore)
	fmt.Printf("SVID Valid Until:\t%v\n", svid.NotAfter)
	for i, ca := range svidBundle {
		num := i + 1
		fmt.Printf("CA #%v Valid After:\t%v\n", num, ca.NotBefore)
		fmt.Printf("CA #%v Valid Until:\t%v\n", num, ca.NotAfter)
	}

	if len(federatedBundleIDs) > 0 {
		idList := strings.Join(federatedBundleIDs, ", ")
		fmt.Printf("Federated with: %v", idList)
	}
}

func (f APIFetch) writeBundles(bundles *workload.Bundles) error {
	for i, bundle := range bundles.Bundles {
		svidName := fmt.Sprintf("svid.%v.pem", i)
		keyName := fmt.Sprintf("svid.%v.key", i)
		bundleName := fmt.Sprintf("bundle.%v.pem", i)
		fBundleName := fmt.Sprintf("federated_bundle.%v.pem", i)

		err := f.writeCerts(svidName, bundle.Svid)
		if err != nil {
			return err
		}

		err = f.writeKey(keyName, bundle.SvidPrivateKey)
		if err != nil {
			return err
		}

		err = f.writeCerts(bundleName, bundle.SvidBundle)
		if err != nil {
			return err
		}

		// Collapse federated bundles
		// TODO: Validate SPIFFE ID of CA certs against the
		// ID returned from the workload API
		fBundles := []byte{}
		for _, b := range bundle.FederatedBundles {
			fBundles = append(fBundles, b...)
		}
		if len(fBundles) > 0 {
			err = f.writeCerts(fBundleName, fBundles)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeCerts takes a slice of data, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to filename
func (f APIFetch) writeCerts(filename string, data []byte) error {
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
func (f APIFetch) writeKey(filename string, data []byte) error {
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}

	return f.writeFile(filename, pem.EncodeToMemory(b))
}

// writeFile creates or truncates filename, and writes data to it
func (f APIFetch) writeFile(filename string, data []byte) error {
	p := path.Join(f.config.writePath, filename)
	return ioutil.WriteFile(p, data, os.ModePerm)
}

func (f APIFetch) dial() (workload.WorkloadClient, error) {
	// Workload API is unauthenticated
	conn, err := grpc.Dial(f.config.socketPath, grpc.WithInsecure(), grpc.WithDialer(f.dialer))
	if err != nil {
		return nil, err
	}

	return workload.NewWorkloadClient(conn), nil
}

// dialer gets passed to grpc and serves as the mechanism for
// calling a unix domain socket.
// TODO: is there a better way to do this?
func (f APIFetch) dialer(addr string, timeout time.Duration) (net.Conn, error) {
	// Assume we're only dialing sockets
	return net.DialTimeout("unix", addr, timeout)
}
