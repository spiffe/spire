package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSPIFFEID(t *testing.T) {
	output := `Received 1 bundle after 10.067711ms

SPIFFE ID:              spiffe://example.org/ns/spire/sa/default
SVID Valid After:       2019-07-17 15:58:59 +0000 UTC
SVID Valid Until:       2019-07-17 16:59:09 +0000 UTC
CA #1 Valid After:      2019-07-17 15:58:41 +0000 UTC
CA #1 Valid Until:      2019-07-18 03:58:51 +0000 UTC
`

	id, ok := ExtractSPIFFEID(output)
	if assert.True(t, ok) {
		assert.Equal(t, "spiffe://example.org/ns/spire/sa/default", id)
	}

}
