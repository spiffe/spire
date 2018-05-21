package sql

import (
	"reflect"
	"testing"
)

func TestBundleAppend(t *testing.T) {
	cert1 := CACert{
		Cert: []byte{'a'},
	}
	cert2 := CACert{
		Cert: []byte{'b'},
	}

	b := Bundle{
		CACerts: []CACert{cert1},
	}

	expected := []CACert{cert1, cert2}
	b.Append(cert2)
	if !reflect.DeepEqual(b.CACerts, expected) {
		t.Errorf("wanted: %v; got: %v", expected, b.CACerts)
	}
}

func TestBundleContains(t *testing.T) {
	cert1 := CACert{
		Cert: []byte{'a'},
	}
	cert2 := CACert{
		Cert: []byte{'b'},
	}

	b := Bundle{
		CACerts: []CACert{cert1},
	}

	if !b.Contains(cert1) {
		t.Error("wanted true; got false")
	}

	if b.Contains(cert2) {
		t.Error("wanted false; got true")
	}
}
