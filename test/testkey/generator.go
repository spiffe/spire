package testkey

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

type Generator struct{ keys Keys }

func (g *Generator) GenerateRSA2048Key() (*rsa.PrivateKey, error) { return g.keys.NextRSA2048() }
func (g *Generator) GenerateRSA4096Key() (*rsa.PrivateKey, error) { return g.keys.NextRSA4096() }
func (g *Generator) GenerateEC256Key() (*ecdsa.PrivateKey, error) { return g.keys.NextEC256() }
func (g *Generator) GenerateEC384Key() (*ecdsa.PrivateKey, error) { return g.keys.NextEC384() }
