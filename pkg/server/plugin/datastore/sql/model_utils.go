package sql

import (
	"bytes"
)

func (b *Bundle) Append(cert CACert) {
	b.CACerts = append(b.CACerts, cert)
}

func (b *Bundle) Contains(cert CACert) bool {
	for _, c := range b.CACerts {
		if bytes.Compare(c.Cert, cert.Cert) == 0 {
			return true
		}
	}

	return false
}
