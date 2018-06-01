package client

import (
	"bytes"
	"fmt"

	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
)

type Update struct {
	Entries map[string]*common.RegistrationEntry
	SVIDs   map[string]*node.Svid
	Bundle  []byte
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
		if len(svidStr) < 30 {
			buffer.WriteString(svidStr)
		} else {
			buffer.WriteString(svidStr[:30])
		}
		buffer.WriteString(" ")
	}
	buffer.WriteString("], Bundle: ")
	if u.Bundle != nil && len(u.Bundle) > 0 {
		buffer.WriteString("bytes")
	} else {
		buffer.WriteString("none")
	}
	buffer.WriteString("}")
	return buffer.String()
}
