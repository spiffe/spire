package agentstore

import (
	"context"
	"errors"
	"sync"

	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Deps struct {
	// DataStore is used to retrieve agent information. It MUST be set.
	DataStore datastore.DataStore
}

type AgentStore struct {
	agentstorev0.UnsafeAgentStoreServer

	mu   sync.RWMutex
	deps *Deps
}

func New() *AgentStore {
	return &AgentStore{}
}

func (s *AgentStore) SetDeps(deps Deps) error {
	if deps.DataStore == nil {
		return errors.New("required DataStore dependency is missing")
	}
	s.mu.Lock()
	s.deps = &deps
	s.mu.Unlock()
	return nil
}

func (s *AgentStore) getDeps() (*Deps, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.deps == nil {
		return nil, status.Error(codes.FailedPrecondition, "AgentStore host service has not been initialized")
	}
	return s.deps, nil
}

func (s *AgentStore) GetAgentInfo(ctx context.Context, req *agentstorev0.GetAgentInfoRequest) (*agentstorev0.GetAgentInfoResponse, error) {
	deps, err := s.getDeps()
	if err != nil {
		return nil, err
	}

	attestedNode, err := deps.DataStore.FetchAttestedNode(ctx, req.AgentId)
	if err != nil {
		return nil, err
	}
	if attestedNode == nil {
		return nil, status.Error(codes.NotFound, "no such agent")
	}

	return &agentstorev0.GetAgentInfoResponse{
		Info: &agentstorev0.AgentInfo{
			AgentId: req.AgentId,
		},
	}, nil
}
