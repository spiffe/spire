package spireplugin

import (
	"context"
	"errors"
	"net"

	proto "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/spire/api/workload"
)

func (m *SpirePlugin) getWorkloadSVID(ctx context.Context, config *Configuration) ([]byte, []byte, []byte, error) {
	errorChan := make(chan error, 1)

	wapiClient := m.newWorkloadAPIClient(config.WorkloadAPISocket)
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
			return nil, nil, nil, ctx.Err()
		case err := <-errorChan:
			return nil, nil, nil, err
		}
	}
}

func (m *SpirePlugin) receiveUpdatedCerts(svidResponse *proto.X509SVIDResponse) ([]byte, []byte, []byte, error) {
	if len(svidResponse.Svids) == 0 {
		return nil, nil, nil, errors.New("no X509 SVID in response")
	}
	svid := svidResponse.Svids[0]
	return svid.X509Svid, svid.X509SvidKey, svid.Bundle, nil
}

//newWorkloadAPIClient creates a workload.X509Client
func (m *SpirePlugin) newWorkloadAPIClient(agentAddress string) workload.X509Client {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: agentAddress,
	}
	config := &workload.X509ClientConfig{
		Addr: addr,
	}
	return workload.NewX509Client(config)
}
