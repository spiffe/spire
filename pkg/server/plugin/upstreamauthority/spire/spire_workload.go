package spireplugin

import (
	"context"
	"errors"
	"net"

	"github.com/hashicorp/go-hclog"
	proto "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/spire/api/workload"
	"github.com/spiffe/spire/proto/spire/api/node"
)

func (m *Plugin) watchWorkloadSVID(ctx context.Context, workloadAPISocket string, ready chan struct{}) {
	errorChan := make(chan error, 1)
	wapiClient := m.newWorkloadAPIClient(workloadAPISocket)
	updateChan := wapiClient.UpdateChan()
	go func() {
		err := wapiClient.Start()
		if err != nil {
			errorChan <- err
		}
	}()
	defer wapiClient.Stop()

	firstDone := false
	for {
		select {
		case svidResponse := <-updateChan:
			wCert, wKey, wBundle, err := m.receiveUpdatedCerts(svidResponse)
			if err != nil {
				m.log.Error("cannot receive workload SVID update", "error", err)
				continue
			}

			conn, err := m.newNodeClientConn(ctx, wCert, wKey, wBundle)
			if err != nil {
				m.log.Error("cannot create node client gRPC connection", "error", err)
				continue
			}

			m.nodeMtx.Lock()
			if m.conn != nil {
				m.conn.Close()
			}
			m.conn = conn
			m.nodeClient = node.NewNodeClient(m.conn)
			m.nodeMtx.Unlock()

			if !firstDone {
				firstDone = true
				close(ready)
			}

		case <-ctx.Done():
			m.log.Debug("watch workload context done", "reason", ctx.Err())
			return

		case err := <-errorChan:
			m.log.Error("workload API error", "error", err)
		}
	}
}

func (m *Plugin) receiveUpdatedCerts(svidResponse *proto.X509SVIDResponse) ([]byte, []byte, []byte, error) {
	if len(svidResponse.Svids) == 0 {
		return nil, nil, nil, errors.New("no X509 SVID in response")
	}
	svid := svidResponse.Svids[0]
	return svid.X509Svid, svid.X509SvidKey, svid.Bundle, nil
}

//newWorkloadAPIClient creates a workload.X509Client
func (m *Plugin) newWorkloadAPIClient(agentAddress string) workload.X509Client {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: agentAddress,
	}
	config := &workload.X509ClientConfig{
		Addr: addr,
		Log:  m.log.StandardLogger(&hclog.StandardLoggerOptions{}),
	}
	return workload.NewX509Client(config)
}
