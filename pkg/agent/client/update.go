package client

import (
	"bytes"
	"fmt"

	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
)

type Update struct {
	Entries map[string]*common.RegistrationEntry
	SVIDs   map[string]*node.X509SVID
	Bundles map[string]*common.Bundle
}

func (u *Update) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("{ Entries: [")
	for _, re := range u.Entries {
		buffer.WriteString("{ spiffeID: ")
		buffer.WriteString(re.SpiffeId)
		buffer.WriteString(", parentID: ")
		buffer.WriteString(re.ParentId)
		buffer.WriteString(", selectors: ")
		buffer.WriteString(fmt.Sprintf("%v", re.Selectors))
		buffer.WriteString("}")
	}
	buffer.WriteString("], SVIDs: [")
	for spiffeid, svid := range u.SVIDs {
		buffer.WriteString(spiffeid)
		buffer.WriteString(": ")
		svidStr := svid.String()
		if len(svidStr) < 40 {
			buffer.WriteString(svidStr)
		} else {
			buffer.WriteString(svidStr[:40])
		}
		buffer.WriteString(" ")
	}
	buffer.WriteString("], Bundles: [")
	for spiffeid := range u.Bundles {
		buffer.WriteString(spiffeid)
		buffer.WriteString(" ")
	}
	buffer.WriteString("]}")
	return buffer.String()
}
