package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/data_store"
	"github.com/spiffe/control-plane/plugins/data_store/proto"
)

type SqlitePlugin struct{}

func (SqlitePlugin) CreateFederatedEntry(*proto.CreateFederatedEntryRequest) (*proto.CreateFederatedEntryResponse, error) {
	return &proto.CreateFederatedEntryResponse{}, nil
}

func (SqlitePlugin) ListFederatedEntry(*proto.ListFederatedEntryRequest) (*proto.ListFederatedEntryResponse, error) {
	return &proto.ListFederatedEntryResponse{}, nil
}

func (SqlitePlugin) UpdateFederatedEntry(*proto.UpdateFederatedEntryRequest) (*proto.UpdateFederatedEntryResponse, error) {
	return &proto.UpdateFederatedEntryResponse{}, nil
}

func (SqlitePlugin) DeleteFederatedEntry(*proto.DeleteFederatedEntryRequest) (*proto.DeleteFederatedEntryResponse, error) {
	return &proto.DeleteFederatedEntryResponse{}, nil
}

//

func (SqlitePlugin) CreateAttestedNodeEntry(*proto.CreateAttestedNodeEntryRequest) (*proto.CreateAttestedNodeEntryResponse, error) {
	return &proto.CreateAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) FetchAttestedNodeEntry(*proto.FetchAttestedNodeEntryRequest) (*proto.FetchAttestedNodeEntryResponse, error) {
	return &proto.FetchAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) FetchStaleNodeEntries(*proto.FetchStaleNodeEntriesRequest) (*proto.FetchStaleNodeEntriesResponse, error) {
	return &proto.FetchStaleNodeEntriesResponse{}, nil
}

func (SqlitePlugin) UpdateAttestedNodeEntry(*proto.UpdateAttestedNodeEntryRequest) (*proto.UpdateAttestedNodeEntryResponse, error) {
	return &proto.UpdateAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) DeleteAttestedNodeEntry(*proto.DeleteAttestedNodeEntryRequest) (*proto.DeleteAttestedNodeEntryResponse, error) {
	return &proto.DeleteAttestedNodeEntryResponse{}, nil
}

//

func (SqlitePlugin) CreateNodeResolverMapEntry(*proto.CreateNodeResolverMapEntryRequest) (*proto.CreateNodeResolverMapEntryResponse, error) {
	return &proto.CreateNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) FetchNodeResolverMapEntry(*proto.FetchNodeResolverMapEntryRequest) (*proto.FetchNodeResolverMapEntryResponse, error) {
	return &proto.FetchNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) DeleteNodeResolverMapEntry(*proto.DeleteNodeResolverMapEntryRequest) (*proto.DeleteNodeResolverMapEntryResponse, error) {
	return &proto.DeleteNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) RectifyNodeResolverMapEntries(*proto.RectifyNodeResolverMapEntriesRequest) (*proto.RectifyNodeResolverMapEntriesResponse, error) {
	return &proto.RectifyNodeResolverMapEntriesResponse{}, nil
}

//

func (SqlitePlugin) CreateRegistrationEntry(*proto.CreateRegistrationEntryRequest) (*proto.CreateRegistrationEntryResponse, error) {
	return &proto.CreateRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) FetchRegistrationEntry(*proto.FetchRegistrationEntryRequest) (*proto.FetchRegistrationEntryResponse, error) {
	return &proto.FetchRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) UpdateRegistrationEntry(*proto.UpdateRegistrationEntryRequest) (*proto.UpdateRegistrationEntryResponse, error) {
	return &proto.UpdateRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) DeleteRegistrationEntry(*proto.DeleteRegistrationEntryRequest) (*proto.DeleteRegistrationEntryResponse, error) {
	return &proto.DeleteRegistrationEntryResponse{}, nil
}

//

func (SqlitePlugin) ListParentIDEntries(*proto.ListParentIDEntriesRequest) (*proto.ListParentIDEntriesResponse, error) {
	return &proto.ListParentIDEntriesResponse{}, nil
}

func (SqlitePlugin) ListSelectorEntries(*proto.ListSelectorEntriesRequest) (*proto.ListSelectorEntriesResponse, error) {
	return &proto.ListSelectorEntriesResponse{}, nil
}

func (SqlitePlugin) ListSpiffeEntries(*proto.ListSpiffeEntriesRequest) (*proto.ListSpiffeEntriesResponse, error) {
	return &proto.ListSpiffeEntriesResponse{}, nil
}

//

func (SqlitePlugin) Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error) {
	return &common.ConfigureResponse{}, nil
}

func (SqlitePlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: datastore.Handshake,
		Plugins: map[string]plugin.Plugin{
			"ds_sqlite": datastore.DataStorePlugin{DataStoreImpl: &SqlitePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
