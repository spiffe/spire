package api

import (
	"crypto/x509"
	"fmt"
	"time"
)

func printX509SVIDResponse(svids []*X509SVID, respTime time.Duration) {
	lenMsg := fmt.Sprintf("Received %d svid", len(svids))
	if len(svids) != 1 {
		lenMsg += "s"
	}
	lenMsg += fmt.Sprintf(" after %s", respTime)

	fmt.Println(lenMsg)
	for _, svid := range svids {
		fmt.Println()
		printX509SVID(svid)
		for trustDomain, bundle := range svid.FederatedBundles {
			printX509FederatedBundle(trustDomain, bundle)
		}
	}

	fmt.Println()
}

func printX509SVID(svid *X509SVID) {
	// Print SPIFFE ID first so if we run into a problem, we
	// get to know which record it was
	fmt.Printf("SPIFFE ID:\t\t%s\n", svid.SPIFFEID)

	fmt.Printf("SVID Valid After:\t%v\n", svid.Certificates[0].NotBefore)
	fmt.Printf("SVID Valid Until:\t%v\n", svid.Certificates[0].NotAfter)
	for i, intermediate := range svid.Certificates[1:] {
		num := i + 1
		fmt.Printf("Intermediate #%v Valid After:\t%v\n", num, intermediate.NotBefore)
		fmt.Printf("Intermediate #%v Valid Until:\t%v\n", num, intermediate.NotAfter)
	}
	for i, ca := range svid.Bundle {
		num := i + 1
		fmt.Printf("CA #%v Valid After:\t%v\n", num, ca.NotBefore)
		fmt.Printf("CA #%v Valid Until:\t%v\n", num, ca.NotAfter)
	}
}

func printX509FederatedBundle(trustDomain string, bundle []*x509.Certificate) {
	for i, ca := range bundle {
		num := i + 1
		fmt.Printf("[%s] CA #%v Valid After:\t%v\n", trustDomain, num, ca.NotBefore)
		fmt.Printf("[%s] CA #%v Valid Until:\t%v\n", trustDomain, num, ca.NotAfter)
	}
}
