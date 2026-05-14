package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const certsURL = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.md"

type regionEntry struct {
	Name  string            // e.g. "US East (N. Virginia)"
	Certs map[string]string // cert type → PEM, e.g. "RSA" → "-----BEGIN CERTIFICATE-----\n..."
}

var (
	regionRE   = regexp.MustCompile(`^##\s+(.+?)\s+—\s+([a-z]+-(?:[a-z]+-)+\d+)`)
	certTypeRE = regexp.MustCompile(`^####\s+\[\s*(.+?)\s*\]`)
)

func fetchCerts() (map[string]regionEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(certsURL)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", certsURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", certsURL, resp.Status)
	}
	return parseCerts(resp.Body)
}

// parseCerts parses the AWS regions-certs markdown page and returns a map
// from region code to its display name and certificates, keyed by type ("RSA", "RSA-2048").
//
// The markdown structure is:
//
//	## US East (N. Virginia) — us-east-1
//	#### [ RSA ]
//	```
//	-----BEGIN CERTIFICATE-----
//	...
//	-----END CERTIFICATE-----
//	```
func parseCerts(r io.Reader) (map[string]regionEntry, error) {
	regions := make(map[string]regionEntry)
	var current regionEntry
	var currentCode, currentType string
	var inFence, inCert bool
	var certLines []string

	flush := func() {
		if currentCode != "" && currentType != "" && len(certLines) > 0 {
			if _, exists := current.Certs[currentType]; !exists {
				current.Certs[currentType] = strings.Join(certLines, "\n") + "\n"
			}
		}
		certLines = nil
		inCert = false
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if m := regionRE.FindStringSubmatch(line); m != nil {
			flush()
			if currentCode != "" {
				regions[currentCode] = current
			}
			currentCode = m[2]
			current = regionEntry{Name: m[1], Certs: make(map[string]string)}
			currentType = ""
			inFence = false
			continue
		}

		if m := certTypeRE.FindStringSubmatch(line); m != nil {
			flush()
			currentType = m[1]
			inFence = false
			continue
		}

		if strings.HasPrefix(line, "```") {
			if !inFence {
				inFence = true
			} else {
				inFence = false
				flush()
			}
			continue
		}

		if inFence {
			if strings.TrimSpace(line) == "-----BEGIN CERTIFICATE-----" {
				inCert = true
			}
			if inCert {
				certLines = append(certLines, line)
			}
		}
	}
	flush()
	if currentCode != "" {
		regions[currentCode] = current
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	if len(regions) == 0 {
		return nil, errors.New("no certificates found; page structure may have changed")
	}
	return regions, nil
}

// regionVarName converts "us-east-1" to "usEast1".
func regionVarName(code string) string {
	parts := strings.Split(code, "-")
	var sb strings.Builder
	for i, p := range parts {
		if i == 0 {
			sb.WriteString(p)
		} else {
			sb.WriteString(strings.ToUpper(p[:1]) + p[1:])
		}
	}
	return sb.String() + "Cert"
}

// certExpiry parses the NotAfter date from a PEM certificate.
func certExpiry(pemStr string) string {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.NotAfter.Format("Jan 2, 2006")
}

// generateFile produces a cacerts.go source for the given cert type.
//
// certType is "RSA" or "RSA-2048"; packageName is "awsrsa1024" or "awsrsa2048".
func generateFile(packageName string, certType string, regions map[string]regionEntry) ([]byte, error) {
	type entry struct {
		region string
		name   string
		pem    string
	}
	var entries []entry
	for code, r := range regions {
		if pem, ok := r.Certs[certType]; ok {
			entries = append(entries, entry{code, r.Name, pem})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})

	// Deduplicate: group regions that share identical PEM content.
	pemToVar := map[string]string{}       // normalized PEM → var name
	varToPEM := map[string]string{}       // var name → PEM
	varToRegions := map[string][]string{} // var name → all region codes sharing it
	regionToVar := map[string]string{}    // region code → var name

	for _, e := range entries {
		norm := strings.TrimSpace(e.pem)
		if existing, ok := pemToVar[norm]; ok {
			regionToVar[e.region] = existing
			varToRegions[existing] = append(varToRegions[existing], e.region)
		} else {
			varName := regionVarName(e.region)
			pemToVar[norm] = varName
			varToPEM[varName] = e.pem
			regionToVar[e.region] = varName
			varToRegions[varName] = []string{e.region}
		}
	}

	// Collect unique vars in stable order (first appearance wins).
	type varEntry struct {
		name    string
		pem     string
		regions []string
	}
	var vars []varEntry
	seen := map[string]bool{}
	for _, e := range entries {
		vn := regionToVar[e.region]
		if !seen[vn] {
			seen[vn] = true
			vars = append(vars, varEntry{vn, varToPEM[vn], varToRegions[vn]})
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "package %s\n\n", packageName)
	fmt.Fprintln(&buf, "const (")
	for _, v := range vars {
		// One comment line per region sharing this cert, e.g.:
		//   // US East (N. Virginia) — us-east-1
		for _, rc := range v.regions {
			if name := regions[rc].Name; name != "" {
				fmt.Fprintf(&buf, "\t// %s — %s\n", name, rc)
			}
		}
		expiry := certExpiry(v.pem)
		if expiry != "" {
			fmt.Fprintf(&buf, "\t// Expires: %s\n", expiry)
		}
		fmt.Fprintf(&buf, "\t%s = `%s`\n\n", v.name, strings.TrimRight(v.pem, "\n"))
	}
	fmt.Fprintln(&buf, ")")
	fmt.Fprintln(&buf)

	fmt.Fprintln(&buf, "var CACerts = map[string]string{")
	for _, e := range entries {
		fmt.Fprintf(&buf, "\t%q: %s,\n", e.region, regionToVar[e.region])
	}
	fmt.Fprintln(&buf, "}")

	return format.Source(buf.Bytes())
}

func main() {
	regions, err := fetchCerts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	targets := []struct {
		pkg      string
		certType string
		dir      string
	}{
		{"awsrsa1024", "RSA", "pkg/server/plugin/nodeattestor/awsiid/awsrsa1024"},
		{"awsrsa2048", "RSA-2048", "pkg/server/plugin/nodeattestor/awsiid/awsrsa2048"},
	}

	for _, t := range targets {
		path := t.dir + "/cacerts.go"
		src, err := generateFile(t.pkg, t.certType, regions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating %s: %v\n", t.pkg, err)
			os.Exit(1)
		}
		if err := os.MkdirAll(t.dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating dir %s: %v\n", t.dir, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, src, 0o644); err != nil { //nolint:gosec // We do not need or want stricter permissions here
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", path)
	}
}
