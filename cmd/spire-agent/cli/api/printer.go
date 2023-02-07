package api

import (
	"crypto/x509"
	"fmt"
	"time"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func printX509SVIDResponse(env *commoncli.Env, svids []*X509SVID, respTime time.Duration) {
	lenMsg := fmt.Sprintf("Received %d svid", len(svids))
	if len(svids) != 1 {
		lenMsg += "s"
	}
	lenMsg += fmt.Sprintf(" after %s", respTime)

	env.Println(lenMsg)
	for _, svid := range svids {
		env.Println()
		printX509SVID(env, svid)
		for trustDomain, bundle := range svid.FederatedBundles {
			printX509FederatedBundle(env, trustDomain, bundle)
		}
	}

	env.Println()
}

func printX509SVID(env *commoncli.Env, svid *X509SVID) {
	// Print SPIFFE ID first so if we run into a problem, we
	// get to know which record it was
	env.Printf("SPIFFE ID:\t\t%s\n", svid.SPIFFEID)

	env.Printf("SVID Valid After:\t%v\n", svid.Certificates[0].NotBefore)
	env.Printf("SVID Valid Until:\t%v\n", svid.Certificates[0].NotAfter)
	for i, intermediate := range svid.Certificates[1:] {
		num := i + 1
		env.Printf("Intermediate #%v Valid After:\t%v\n", num, intermediate.NotBefore)
		env.Printf("Intermediate #%v Valid Until:\t%v\n", num, intermediate.NotAfter)
	}
	for i, ca := range svid.Bundle {
		num := i + 1
		env.Printf("CA #%v Valid After:\t%v\n", num, ca.NotBefore)
		env.Printf("CA #%v Valid Until:\t%v\n", num, ca.NotAfter)
	}
}

func printX509FederatedBundle(env *commoncli.Env, trustDomain string, bundle []*x509.Certificate) {
	for i, ca := range bundle {
		num := i + 1
		env.Printf("[%s] CA #%v Valid After:\t%v\n", trustDomain, num, ca.NotBefore)
		env.Printf("[%s] CA #%v Valid Until:\t%v\n", trustDomain, num, ca.NotAfter)
	}
}
