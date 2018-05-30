package manager

import (
	"fmt"
	"sync"

	"github.com/spiffe/spire/pkg/agent/client"
)

type clientsPool struct {
	// Map of client connections to the server keyed by SPIFFEID
	clients map[string]client.Client
	// Protects access to the pool.
	m *sync.Mutex
}

func (p *clientsPool) add(spiffeID string, client client.Client) {
	// If there is already a client with the specified spiffeID, close it first.
	if c := p.get(spiffeID); c != nil {
		c.Release()
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.clients[spiffeID] = client
}

func (p *clientsPool) get(spiffeID string) client.Client {
	p.m.Lock()
	defer p.m.Unlock()
	return p.clients[spiffeID]
}

// close releases the pool's resources.
func (p *clientsPool) close() {
	p.m.Lock()
	defer p.m.Unlock()
	for _, c := range p.clients {
		c.Release()
	}
}

// addClient adds client.Client to the pool and associates it to the specified list of spiffeIDs.
func (m *manager) addClient(cli client.Client, spiffeIDs ...string) error {
	// If there is no pool yet, create one.
	m.mtx.Lock()
	if m.syncClients == nil {
		m.syncClients = &clientsPool{clients: map[string]client.Client{}, m: &sync.Mutex{}}
	}
	m.mtx.Unlock()

	for _, id := range spiffeIDs {
		m.syncClients.add(id, cli)
	}

	return nil
}

func (m *manager) ensureSyncClient(spiffeID string) (client.Client, error) {
	currentCli := m.syncClients.get(spiffeID)
	if currentCli == nil {
		return nil, fmt.Errorf("no client found for %s", spiffeID)
	}
	return currentCli, nil
}
