package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseCerts(t *testing.T) {
	f, err := os.Open("testdata/regions-certs.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	regions, err := parseCerts(f)
	if err != nil {
		t.Fatalf("parseCerts: %v", err)
	}

	want := map[string]struct {
		name      string
		certTypes []string
	}{
		"us-east-1":      {"US East (N. Virginia)", []string{"DSA", "RSA", "RSA-2048"}},
		"us-west-2":      {"US West (Oregon)", []string{"DSA", "RSA", "RSA-2048"}},
		"eusc-de-east-1": {"AWS European Sovereign Cloud", []string{"DSA", "RSA", "RSA-2048"}},
	}

	if len(regions) != len(want) {
		t.Errorf("got %d regions, want %d", len(regions), len(want))
	}

	for code, w := range want {
		r, ok := regions[code]
		if !ok {
			t.Errorf("region %q missing", code)
			continue
		}
		if r.Name != w.name {
			t.Errorf("region %q: name = %q, want %q", code, r.Name, w.name)
		}
		for _, ct := range w.certTypes {
			pem, ok := r.Certs[ct]
			if !ok {
				t.Errorf("region %q: cert type %q missing", code, ct)
				continue
			}
			if !strings.Contains(pem, "-----BEGIN CERTIFICATE-----") {
				t.Errorf("region %q cert type %q: missing PEM header", code, ct)
			}
		}
	}

	// us-east-1 and us-west-2 share the same RSA body in the fixture.
	if regions["us-east-1"].Certs["RSA"] != regions["us-west-2"].Certs["RSA"] {
		t.Error("us-east-1 and us-west-2 should have identical RSA certs in the fixture")
	}
}

func TestParseCertsEmpty(t *testing.T) {
	_, err := parseCerts(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("unexpected error: %v", err)
	}
}
