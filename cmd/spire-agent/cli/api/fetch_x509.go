package api

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"path"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

func NewFetchX509Command() cli.Command {
	return newFetchX509Command(commoncli.DefaultEnv, newWorkloadClient)
}

func newFetchX509Command(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &fetchX509Command{env: env})
}

type fetchX509Command struct {
	silent    bool
	writePath string
	env       *commoncli.Env
	printer   cliprinter.Printer
	respTime  time.Duration
}

func (*fetchX509Command) name() string {
	return "fetch x509"
}

func (*fetchX509Command) synopsis() string {
	return "Fetches X509 SVIDs from the Workload API"
}

func (c *fetchX509Command) run(ctx context.Context, _ *commoncli.Env, client *workloadClient) error {
	start := time.Now()
	resp, err := c.fetchX509SVID(ctx, client)
	c.respTime = time.Since(start)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func (c *fetchX509Command) appendFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.silent, "silent", false, "Suppress stdout")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional; only available for pretty output format)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintFetchX509)
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

func (c *fetchX509Command) writeResponse(svids []*X509SVID) error {
	for i, svid := range svids {
		svidPath := path.Join(c.writePath, fmt.Sprintf("svid.%v.pem", i))
		keyPath := path.Join(c.writePath, fmt.Sprintf("svid.%v.key", i))
		bundlePath := path.Join(c.writePath, fmt.Sprintf("bundle.%v.pem", i))

		c.env.Printf("Writing SVID #%d to file %s.\n", i, svidPath)
		err := c.writeCerts(svidPath, svid.Certificates)
		if err != nil {
			return err
		}

		c.env.Printf("Writing key #%d to file %s.\n", i, keyPath)
		err = c.writeKey(keyPath, svid.PrivateKey)
		if err != nil {
			return err
		}

		c.env.Printf("Writing bundle #%d to file %s.\n", i, bundlePath)
		err = c.writeCerts(bundlePath, svid.Bundle)
		if err != nil {
			return err
		}

		// sort and write the keys by trust domain so the output is consistent
		federatedDomains := make([]string, 0, len(svid.FederatedBundles))
		for trustDomain := range svid.FederatedBundles {
			federatedDomains = append(federatedDomains, trustDomain)
		}

		for j, trustDomain := range federatedDomains {
			bundlePath := path.Join(c.writePath, fmt.Sprintf("federated_bundle.%d.%d.pem", i, j))
			c.env.Printf("Writing federated bundle #%d for trust domain %s to file %s.\n", j, trustDomain, bundlePath)
			err = c.writeCerts(bundlePath, svid.FederatedBundles[trustDomain])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeCerts takes a slice of data, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to filename
func (c *fetchX509Command) writeCerts(filename string, certs []*x509.Certificate) error {
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
func (c *fetchX509Command) writeKey(filename string, privateKey crypto.PrivateKey) error {
	data, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}

	return diskutil.WritePrivateFile(filename, pem.EncodeToMemory(b))
}

// writeFile creates or truncates filename, and writes data to it
func (c *fetchX509Command) writeFile(filename string, data []byte) error {
	return diskutil.WritePubliclyReadableFile(filename, data)
}

func (c *fetchX509Command) prettyPrintFetchX509(env *commoncli.Env, results ...interface{}) error {
	resp, ok := results[0].(*workload.X509SVIDResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	svids, err := parseAndValidateX509SVIDResponse(resp)
	if err != nil {
		return err
	}

	if !c.silent {
		printX509SVIDResponse(env, svids, c.respTime)
	}

	if c.writePath != "" {
		if err := c.writeResponse(svids); err != nil {
			return err
		}
	}

	return nil
}

type X509SVID struct {
	SPIFFEID         string
	Hint             string
	Certificates     []*x509.Certificate
	PrivateKey       crypto.Signer
	Bundle           []*x509.Certificate
	FederatedBundles map[string][]*x509.Certificate
}

func parseAndValidateX509SVIDResponse(resp *workload.X509SVIDResponse) ([]*X509SVID, error) {
	svids, err := parseX509SVIDResponse(resp)
	if err != nil {
		return nil, err
	}
	if err := validateX509SVIDs(svids); err != nil {
		return nil, err
	}
	return svids, nil
}

func parseX509SVIDResponse(resp *workload.X509SVIDResponse) ([]*X509SVID, error) {
	if len(resp.Svids) == 0 {
		return nil, errors.New("workload response contains no svids")
	}

	federatedBundles := make(map[string][]*x509.Certificate)
	for federatedDomainID, federatedBundleDER := range resp.FederatedBundles {
		federatedBundle, err := x509.ParseCertificates(federatedBundleDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundle for federated domain %q: %w", federatedDomainID, err)
		}
		if len(federatedBundle) == 0 {
			return nil, fmt.Errorf("no certificates in bundle for federated domain %q", federatedDomainID)
		}
		federatedBundles[federatedDomainID] = federatedBundle
	}

	var svids []*X509SVID
	for i, respSVID := range resp.Svids {
		svid, err := parseX509SVID(respSVID, federatedBundles)
		if err != nil {
			return nil, fmt.Errorf("failed to parse svid entry %d for spiffe id %q: %w", i, respSVID.SpiffeId, err)
		}
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseX509SVID(svid *workload.X509SVID, federatedBundles map[string][]*x509.Certificate) (*X509SVID, error) {
	certificates, err := x509.ParseCertificates(svid.X509Svid)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, errors.New("no certificates found")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is type %T, not crypto.Signer", privateKey)
	}
	bundle, err := x509.ParseCertificates(svid.Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust bundle: %w", err)
	}
	if len(bundle) == 0 {
		return nil, errors.New("no certificates in trust bundle")
	}

	return &X509SVID{
		SPIFFEID:         svid.SpiffeId,
		PrivateKey:       signer,
		Certificates:     certificates,
		Bundle:           bundle,
		FederatedBundles: federatedBundles,
		Hint:             svid.Hint,
	}, nil
}

func validateX509SVIDs(svids []*X509SVID) error {
	for _, svid := range svids {
		if err := validateX509SVID(svid); err != nil {
			return err
		}
	}
	return nil
}

func validateX509SVID(svid *X509SVID) error {
	id, err := spiffeid.FromString(svid.SPIFFEID)
	if err != nil {
		return err
	}

	bundle := x509bundle.FromX509Authorities(id.TrustDomain(), svid.Bundle)

	if _, _, err := x509svid.Verify(svid.Certificates, bundle); err != nil {
		return fmt.Errorf("%q SVID failed verification against bundle: %w", svid.SPIFFEID, err)
	}

	return nil
}
