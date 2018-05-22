package attestor

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
)

type attestor struct {
	c *Config
}

type Attestor interface {
	Attest(pid int32) []*common.Selector
}

func New(config *Config) Attestor {
	return &attestor{c: config}
}

type Config struct {
	Catalog catalog.Catalog
	L       logrus.FieldLogger
	T       telemetry.Sink
}

const (
	workloadApi    = "workload_api"
	workloadPid    = "workload_pid"
	workloadAttDur = "workload_attestation_duration"
	unknownName    = "unknown"
)

// Attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (wla *attestor) Attest(pid int32) []*common.Selector {
	tLabels := []telemetry.Label{{workloadPid, string(pid)}}
	defer wla.c.T.MeasureSinceWithLabels([]string{workloadApi, workloadAttDur}, time.Now(), tLabels)

	plugins := wla.c.Catalog.WorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go wla.invokeAttestor(p, pid, sChan, errChan)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for i := 0; i < len(plugins); i++ {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
		case err := <-errChan:
			wla.c.L.Errorf("Failed to collect all selectors for PID %v: %v", pid, err)
		}
	}

	wla.c.T.AddSampleWithLabels([]string{workloadApi, "discovered_selectors"}, float32(len(selectors)), tLabels)
	wla.c.L.Debugf("PID %v attested to have selectors %v", pid, selectors)
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(a workloadattestor.WorkloadAttestor, pid int32, sChan chan []*common.Selector, errChan chan error) {
	attestorName := wla.attestorName(a)
	tLabels := []telemetry.Label{{workloadPid, string(pid)}, {"attestor_name", attestorName}}

	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	start := time.Now()
	resp, err := a.Attest(req)

	// Capture the attestor latency metrics regardless of whether an error condition was encountered or not
	wla.c.T.MeasureSinceWithLabels([]string{workloadApi, "workload_attestor_latency"}, start, tLabels)
	if err != nil {
		errChan <- fmt.Errorf("call %v workload attestor: %v", attestorName, err)
		return
	}

	sChan <- resp.Selectors
	return
}

// attestorName attempts to find the name of a workload attestor, given the WorkloadAttestor interface.
func (wla *attestor) attestorName(a workloadattestor.WorkloadAttestor) string {
	mp := wla.c.Catalog.Find(a)
	if mp == nil {
		return unknownName
	}

	return mp.Config.PluginName
}
