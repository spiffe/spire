package spireplugin

import (
	"context"
	"net"
	"time"

	"github.com/spiffe/spire/api/workload"
	proto "github.com/spiffe/spire/proto/api/workload"
)

func (m *spirePlugin) getWorkloadSVID(ctx context.Context, config *Configuration) ([]byte, []byte, []byte, error) {
	errorChan := make(chan error, 1)

	duration := time.Duration(2 * time.Second) // TODO: Make this timeout configurable?
	wapiClient := m.newWorkloadAPIClient(config.WorkloadAPISocket, duration)
	updateChan := wapiClient.UpdateChan()
	go func() {
		err := wapiClient.Start()
		if err != nil {
			errorChan <- err
		}
	}()

	defer wapiClient.Stop()

	for {
		select {
		case svidResponse := <-updateChan:
			return m.receiveUpdatedCerts(svidResponse)
		case <-ctx.Done():
			return []byte{}, []byte{}, []byte{}, ctx.Err()
		case err := <-errorChan:
			return []byte{}, []byte{}, []byte{}, err
		}
	}
}

func (m *spirePlugin) receiveUpdatedCerts(svidResponse *proto.X509SVIDResponse) ([]byte, []byte, []byte, error) {
	svid := svidResponse.Svids[0]
	return svid.X509Svid, svid.X509SvidKey, svid.Bundle, nil
}

//newWorkloadAPIClient creates a workload.X509Client
func (m *spirePlugin) newWorkloadAPIClient(agentAddress string, timeout time.Duration) workload.X509Client {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: agentAddress,
	}
	config := &workload.X509ClientConfig{
		Addr:    addr,
		Timeout: timeout,
	}
	return workload.NewX509Client(config)
}
