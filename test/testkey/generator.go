package testkey

import (
	"crypto"
)

type Generator struct{ keys Keys }

func (g *Generator) GenerateRSA2048Key() (crypto.Signer, error) { return g.keys.NextRSA2048() }
func (g *Generator) GenerateRSA4096Key() (crypto.Signer, error) { return g.keys.NextRSA4096() }
func (g *Generator) GenerateEC256Key() (crypto.Signer, error)   { return g.keys.NextEC256() }
func (g *Generator) GenerateEC384Key() (crypto.Signer, error)   { return g.keys.NextEC384() }
