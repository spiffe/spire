package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/test/integration/setup/itclient"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: checkstoredsvids storageFile")
		os.Exit(1)
	}
	storageFile := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := itclient.NewLocalServerClient(ctx)
	defer client.Release()

	entriesResp := getEntries(ctx, client)

	storedSVIDS := getSVIDsFromFile(storageFile)

	currentBundle := getCurrentBundle(ctx, client)

	assertStoredSVIDs(entriesResp, storedSVIDS, currentBundle)
}

func getCurrentBundle(ctx context.Context, client *itclient.LocalServerClient) []*x509.Certificate {
	bundleClient := client.BundleClient()
	bundlesResp, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		log.Fatalf("failed to get bundle: %v", err)
	}
	var x509Authorities []*x509.Certificate
	for _, x509Authority := range bundlesResp.GetX509Authorities() {
		certs, err := x509.ParseCertificates(x509Authority.Asn1)
		if err != nil {
			log.Fatalf("failed to parse certificate: %v", err)
		}
		x509Authorities = append(x509Authorities, certs...)
	}
	return x509Authorities
}

func getEntries(ctx context.Context, client *itclient.LocalServerClient) *entryv1.ListEntriesResponse {
	entryClient := client.EntryClient()
	entriesResp, err := entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{})
	if err != nil {
		log.Fatalf("failed to list entries: %s", err.Error())
	}
	return entriesResp
}

func assertStoredSVIDs(entries *entryv1.ListEntriesResponse, svids map[string]*svidstorev1.X509SVID, currentBundle []*x509.Certificate) {
	numStoredSVIDS := 0
	for _, entry := range entries.Entries {
		td, err := spiffeid.TrustDomainFromString(entry.SpiffeId.TrustDomain)
		assertNoError(err, "invalid trust domain for entry %q", entry.Id)
		entrySPIFFEID, err := spiffeid.FromPath(td, entry.SpiffeId.Path)
		assertNoError(err, "invalid spiffe id for entry %q", entry.Id)

		secretName, ok := getSecretName(entry.Selectors)
		if !ok || !entry.StoreSvid {
			continue
		}

		storedSVID, stored := svids[secretName]
		if !stored {
			log.Fatalf("svid not found for entry %q, which should be stored", entry.Id)
		}

		// decode ASN.1 DER bundle
		var storedBundle []*x509.Certificate
		for _, bundle := range storedSVID.Bundle {
			ca, err := x509.ParseCertificates(bundle)
			assertNoError(err, "invalid bundle for entry %q", entry.Id)
			storedBundle = append(storedBundle, ca...)
		}
		assertEqualCerts(storedBundle, currentBundle, "bundle certificates do not match for entry %q", entry.Id)

		// decode certChain
		for _, cert := range storedSVID.CertChain {
			_, err := x509.ParseCertificate(cert)
			assertNoError(err, "invalid certificate for entry %q", entry.Id)
		}

		// decode private key
		_, err = x509.ParsePKCS8PrivateKey(storedSVID.PrivateKey)
		assertNoError(err, "invalid private key for entry %q", entry.Id)

		// check spiffe id
		spiffeID, err := spiffeid.FromString(storedSVID.SpiffeID)
		assertNoError(err, "invalid spiffe id for entry %s", entry.Id)
		assertEqual(spiffeID, entrySPIFFEID, "SPIFFE ID does not match for entry %q", entry.Id)

		log.Printf("SVID is correctly stored for entry %q", entry.Id)
		numStoredSVIDS++
	}
	if len(svids) != numStoredSVIDS {
		log.Fatalf("number of stored SVIDs does not match the number of svids that should be stored")
	}
}

func getSVIDsFromFile(storageFile string) map[string]*svidstorev1.X509SVID {
	var storedSVIDS map[string]*svidstorev1.X509SVID

	fileContent, err := os.ReadFile(storageFile)
	if err != nil {
		log.Fatalf("failed to read file: %s", err.Error())
	}

	err = json.Unmarshal(fileContent, &storedSVIDS)
	if err != nil {
		log.Fatalf("failed to unmarshal file data: %s", err.Error())
	}
	return storedSVIDS
}

func getSecretName(selectors []*types.Selector) (string, bool) {
	for _, selector := range selectors {
		if selector.Type == "disk" {
			split := strings.Split(selector.Value, ":")
			key, value := split[0], split[1]
			if key == "name" {
				return value, true
			}
		}
	}
	return "", false
}

func assertNoError(err error, format string, v ...any) {
	if err != nil {
		log.Fatalf(format, v...)
	}
}

func assertEqual(expected, actual any, format string, v ...any) {
	if !reflect.DeepEqual(expected, actual) {
		log.Fatalf(format, v...)
	}
}

func assertEqualCerts(expected, actual []*x509.Certificate, format string, v ...any) {
	if len(expected) != len(actual) {
		log.Fatalf(format, v...)
	}

	for i, cert := range expected {
		if !reflect.DeepEqual(cert, actual[i]) {
			log.Fatalf(format, v...)
		}
	}
}
