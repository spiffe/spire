package fakeagentstore

import (
	"context"
	"sync"

	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentStore struct {
	agentstorev0.UnsafeAgentStoreServer

	mu    sync.RWMutex
	nodes map[string]*agentstorev0.AgentInfo
}

func New() *AgentStore {
	return &AgentStore{
		nodes: make(map[string]*agentstorev0.AgentInfo),
	}
}

func (s *AgentStore) SetAgentInfo(info *agentstorev0.AgentInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[info.AgentId] = info
}

func (s *AgentStore) GetAgentInfo(ctx context.Context, req *agentstorev0.GetAgentInfoRequest) (*agentstorev0.GetAgentInfoResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.nodes[req.AgentId]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such node")
	}
	return &agentstorev0.GetAgentInfoResponse{
		Info: info,
	}, nil
}
