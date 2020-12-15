package fakeagentstore

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentStore struct {
	hostservices.UnsafeAgentStoreServer

	mu    sync.RWMutex
	nodes map[string]*hostservices.AgentInfo
}

func New() *AgentStore {
	return &AgentStore{
		nodes: make(map[string]*hostservices.AgentInfo),
	}
}

func (s *AgentStore) SetAgentInfo(info *hostservices.AgentInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[info.AgentId] = info
}

func (s *AgentStore) GetAgentInfo(ctx context.Context, req *hostservices.GetAgentInfoRequest) (*hostservices.GetAgentInfoResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.nodes[req.AgentId]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such node")
	}
	return &hostservices.GetAgentInfoResponse{
		Info: info,
	}, nil
}
