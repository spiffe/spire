package ciphertrustkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestToken(t *testing.T) {

	Init("https://<CTM-instance>", "<username>", "<password>")
	x, _ := TokenGenerator()
	assert.Contains(t, x.Jwt, "ey")
}
