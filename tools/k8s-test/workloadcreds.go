package main

import (
	"bytes"
	"context"
	"regexp"
	"time"

	"github.com/zeebo/errs"
)

var (
	reSPIFFEID = regexp.MustCompile(`(?m)^SPIFFE ID:\s*(.+)$`)
)

func WaitForWorkloadCreds(ctx context.Context, workloadPod string, expectedID, socketPath string) error {
	ticker := time.NewTimer(time.Second)
	defer ticker.Stop()

	for {
		actualID, ok := tryGetWorkloadSPIFFEID(workloadPod, socketPath)
		if ok {
			if actualID != expectedID {
				return errs.New("expected SPIFFE ID %q; got %q", expectedID, actualID)
			}
			Goodln("Workload pod %s has SPIFFE ID %q.", workloadPod, actualID)
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func tryGetWorkloadSPIFFEID(podName, socketPath string) (string, bool) {
	id, err := getWorkloadSPIFFEID(podName, socketPath)
	if err != nil {
		return "", false
	}
	return id, true
}

func getWorkloadSPIFFEID(podName, socketPath string) (string, error) {
	stdout := new(bytes.Buffer)
	cmd := kubectlCmd("exec",
		"-t",
		podName,
		"--",
		"/opt/spire/bin/spire-agent", "api", "fetch", "-socketPath", socketPath)
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		return "", errs.Wrap(err)
	}

	id, ok := ExtractSPIFFEID(stdout.String())
	if !ok {
		return "", errs.New("no SPIFFE ID in output")
	}

	return id, nil
}

func ExtractSPIFFEID(output string) (string, bool) {
	m := reSPIFFEID.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}
