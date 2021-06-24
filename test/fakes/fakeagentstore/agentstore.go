package fakeagentstore

import (
	"context"
	"sync"

	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentStore struct {
	agentstorev1.UnsafeAgentStoreServer

	mu    sync.RWMutex
	nodes map[string]*agentstorev1.AgentInfo
}

func New() *AgentStore {
	return &AgentStore{
		nodes: make(map[string]*agentstorev1.AgentInfo),
	}
}

func (s *AgentStore) SetAgentInfo(info *agentstorev1.AgentInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[info.AgentId] = info
}

func (s *AgentStore) GetAgentInfo(ctx context.Context, req *agentstorev1.GetAgentInfoRequest) (*agentstorev1.GetAgentInfoResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.nodes[req.AgentId]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such node")
	}
	return &agentstorev1.GetAgentInfoResponse{
		Info: info,
	}, nil
}
