package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/proto/api/workload"
)

func NewFetchX509Command() cli.Command {
	return newFetchX509Command(defaultEnv, newWorkloadClient)
}

func newFetchX509Command(env *env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, new(fetchX509Command))
}

type fetchX509Command struct {
	silent    bool
	writePath string
}

func (*fetchX509Command) name() string {
	return "fetch x509"
}

func (*fetchX509Command) synopsis() string {
	return "Fetches X509 SVIDs from the Workload API"
}

func (c *fetchX509Command) run(ctx context.Context, env *env, client *workloadClient) error {
	start := time.Now()
	resp, err := c.fetchX509SVID(ctx, client)
	respTime := time.Now().Sub(start)
	if err != nil {
		return err
	}

	if !c.silent {
		printX509SVIDResponse(resp, respTime)
	}

	if c.writePath != "" {
		if err := c.writeResponse(resp); err != nil {
			return err
		}
	}

	return nil
}

func (c *fetchX509Command) appendFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.silent, "silent", false, "Suppress stdout")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional)")
}

func (c *fetchX509Command) fetchX509SVID(ctx context.Context, client *workloadClient) (*workload.X509SVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	return stream.Recv()
}

func (c *fetchX509Command) writeResponse(resp *workload.X509SVIDResponse) error {
	for i, svid := range resp.Svids {
		svidPath := path.Join(c.writePath, fmt.Sprintf("svid.%v.pem", i))
		keyPath := path.Join(c.writePath, fmt.Sprintf("svid.%v.key", i))
		bundlePath := path.Join(c.writePath, fmt.Sprintf("bundle.%v.pem", i))

		fmt.Printf("Writing SVID #%v to file %v.\n", i, svidPath)
		err := c.writeCerts(svidPath, svid.X509Svid)
		if err != nil {
			return err
		}

		fmt.Printf("Writing key #%v to file %v.\n", i, keyPath)
		err = c.writeKey(keyPath, svid.X509SvidKey)
		if err != nil {
			return err
		}

		fmt.Printf("Writing bundle #%v to file %v.\n", i, bundlePath)
		err = c.writeCerts(bundlePath, svid.Bundle)
		if err != nil {
			return err
		}

		for j, trustDomain := range svid.FederatesWith {
			federatedBundlePath := path.Join(c.writePath, fmt.Sprintf("federated_bundle.%v.%v.pem", j, i))
			fmt.Printf("Writing federated bundle #%v for trust domain %v to file %v.\n", i, trustDomain, federatedBundlePath)
			err = c.writeCerts(federatedBundlePath, resp.FederatedBundles[trustDomain])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeCerts takes a slice of data, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to filename
func (c *fetchX509Command) writeCerts(filename string, data []byte) error {
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

	return c.writeFile(filename, pemData)
}

// writeKey takes a private key, formats as PEM, and writes it to filename
func (c *fetchX509Command) writeKey(filename string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	return c.writeFile(filename, pem.EncodeToMemory(b))
}

// writeFile creates or truncates filename, and writes data to it
func (c *fetchX509Command) writeFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}
