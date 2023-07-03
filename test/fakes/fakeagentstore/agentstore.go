package fakeagentstore

import (
	"context"
	"sync"

	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type agentConfig struct {
	info *agentstorev1.AgentInfo
	err  error
}

type AgentStore struct {
	agentstorev1.UnsafeAgentStoreServer

	mu     sync.RWMutex
	agents map[string]agentConfig
}

func New() *AgentStore {
	return &AgentStore{
		agents: make(map[string]agentConfig),
	}
}

func (s *AgentStore) SetAgentInfo(info *agentstorev1.AgentInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[info.AgentId] = agentConfig{info: info}
}

func (s *AgentStore) SetAgentErr(agentID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agentID] = agentConfig{err: err}
}

func (s *AgentStore) GetAgentInfo(_ context.Context, req *agentstorev1.GetAgentInfoRequest) (*agentstorev1.GetAgentInfoResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, ok := s.agents[req.AgentId]
	switch {
	case !ok:
		return nil, status.Error(codes.NotFound, "no such node")
	case agent.err != nil:
		return nil, agent.err
	default:
		return &agentstorev1.GetAgentInfoResponse{
			Info: agent.info,
		}, nil
	}
}
