package api

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
)

func printX509SVIDResponse(resp *workload.X509SVIDResponse, respTime time.Duration) {
	lenMsg := fmt.Sprintf("Received %v bundle", len(resp.Svids))
	if len(resp.Svids) != 1 {
		lenMsg = lenMsg + "s"
	}
	lenMsg = lenMsg + fmt.Sprintf(" after %s", respTime)

	fmt.Println(lenMsg)
	for _, s := range resp.Svids {
		fmt.Println()
		printX509SVID(s)
		for _, trustDomain := range s.FederatesWith {
			printX509FederatedBundle(resp, trustDomain)
		}
	}

	fmt.Println()
}

func printX509SVID(msg *workload.X509SVID) {
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

func printX509FederatedBundle(resp *workload.X509SVIDResponse, trustDomain string) {
	federatedBundle, err := x509.ParseCertificates(resp.FederatedBundles[trustDomain])
	if err != nil {
		fmt.Printf("ERROR: Could not parse CA Certificates of federated bundle: %s\n", err)
		return
	}

	for i, ca := range federatedBundle {
		num := i + 1
		fmt.Printf("[%s] CA #%v Valid After:\t%v\n", trustDomain, num, ca.NotBefore)
		fmt.Printf("[%s] CA #%v Valid Until:\t%v\n", trustDomain, num, ca.NotAfter)
	}
}
