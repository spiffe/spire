package tpmutil

import (
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

func SetAKSRKTemplateECC(t *testing.T, template func() tpm2.Public) {
	original := akSRKTemplateECC
	akSRKTemplateECC = template
	t.Cleanup(func() {
		akSRKTemplateECC = original
	})
}
