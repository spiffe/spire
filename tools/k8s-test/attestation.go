package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
)

var (
	reSignedX509 = regexp.MustCompile(`\"Signed [xX]509 SVID.*\".*(spiffe://[^/]+/spire/agent/[^"]+)\"`)
)

func WaitForNodeAttestation(ctx context.Context, server Object, count int) error {
	svids := make(map[string]bool)

	Infoln("waiting for %d node(s) to attest...", count)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()
	defer pw.Close()

	errch := make(chan error, 2)
	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			nodeID, ok := parseAttestedNodeID(scanner.Text())
			if !ok {
				continue
			}

			if !svids[nodeID] {
				svids[nodeID] = true
				Goodln("node %q attested", nodeID)
				if len(svids) >= count {
					errch <- nil
					cancel()
					return
				}
			}
		}
		errch <- scanner.Err()
	}()
	go func() {
		errch <- kubectlStreamLogs(ctx, server.String(), pw)
	}()

	select {
	case err := <-errch:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if len(svids) < count {
		return fmt.Errorf("expected %d node attestations; got %d", count, len(svids))
	}

	return nil
}

func parseAttestedNodeID(line string) (nodeID string, ok bool) {
	if m := reSignedX509.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}
