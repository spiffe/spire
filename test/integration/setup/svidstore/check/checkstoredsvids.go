package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

	assertStoredSVIDs(entriesResp, storedSVIDS)
}

func getEntries(ctx context.Context, client *itclient.LocalServerClient) *entryv1.ListEntriesResponse {
	entryClient := client.EntryClient()
	entriesResp, err := entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{})
	if err != nil {
		log.Fatal(fmt.Errorf("failed to list entries: %w", err))
	}
	return entriesResp
}

func assertStoredSVIDs(entries *entryv1.ListEntriesResponse, svids map[string]*svidstorev1.X509SVID) {
	numStoredSVIDS := 0
	for _, entry := range entries.Entries {
		secretName, ok := getSecretName(entry.Selectors)
		if !ok || !entry.StoreSvid {
			continue
		}

		storedSVID, stored := svids[secretName]
		if !stored {
			log.Fatalf("svid not found for entry %q, which should be stored", entry.Id)
		}

		// decode ASN.1 DER bundle
		for _, bundle := range storedSVID.Bundle {
			_, err := x509.ParseCertificates(bundle)
			assertNoError(err, "invalid bundle for entry %s", entry.Id)
		}

		// decode certChain
		for _, cert := range storedSVID.CertChain {
			_, err := x509.ParseCertificate(cert)
			assertNoError(err, "invalid certificate for entry %s", entry.Id)
		}

		// decode private key
		_, err := x509.ParsePKCS8PrivateKey(storedSVID.PrivateKey)
		assertNoError(err, "invalid private key for entry %s", entry.Id)

		// check spiffe id
		_, err = spiffeid.FromString(storedSVID.SpiffeID)
		assertNoError(err, "invalid spiffe id for entry %s", entry.Id)

		log.Printf("SVID is correctly stored for entry %s", entry.Id)
		numStoredSVIDS++
	}
	if len(svids) != numStoredSVIDS {
		log.Fatal(fmt.Errorf("number of stored SVIDs does not match the number of svids that should be stored"))
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
