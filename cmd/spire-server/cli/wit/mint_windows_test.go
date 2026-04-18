//go:build windows

package wit

import (
	"github.com/spiffe/spire/test/clitest"
)

var (
	expectedUsage = `Usage of wit mint:
  -keyType string
    	Key type of the WIT-SVID (default "ec-p256")` + clitest.AddrOutputForCasesWhereOptionsStartWithS +
		`  -signingAlgorithm string
    	Signing algorithm for the workload signing key (default "ES256")` + clitest.AddrSocketPathUsageForCasesWhereOptionsStartWithS +
		`  -spiffeID string
    	SPIFFE ID of the WIT-SVID
  -ttl duration
    	TTL of the WIT-SVID
  -write string
    	Directory to write output to instead of stdout
`
)
