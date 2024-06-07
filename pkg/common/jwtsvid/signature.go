package jwtsvid

import "github.com/go-jose/go-jose/v4"

var AllowedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}
