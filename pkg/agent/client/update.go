package client

import "github.com/spiffe/spire/proto/spire/common"

type Update struct {
	Entries map[string]*common.RegistrationEntry
	Bundles map[string]*common.Bundle
}
