package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
	"github.com/spiffe/sri/control_plane/plugins/data_store/proto"
)

type SqlitePlugin struct{}

func (SqlitePlugin) CreateFederatedEntry(*control_plane_proto.CreateFederatedEntryRequest) (*control_plane_proto.CreateFederatedEntryResponse, error) {
	return &control_plane_proto.CreateFederatedEntryResponse{}, nil
}

func (SqlitePlugin) ListFederatedEntry(*control_plane_proto.ListFederatedEntryRequest) (*control_plane_proto.ListFederatedEntryResponse, error) {
	return &control_plane_proto.ListFederatedEntryResponse{}, nil
}

func (SqlitePlugin) UpdateFederatedEntry(*control_plane_proto.UpdateFederatedEntryRequest) (*control_plane_proto.UpdateFederatedEntryResponse, error) {
	return &control_plane_proto.UpdateFederatedEntryResponse{}, nil
}

func (SqlitePlugin) DeleteFederatedEntry(*control_plane_proto.DeleteFederatedEntryRequest) (*control_plane_proto.DeleteFederatedEntryResponse, error) {
	return &control_plane_proto.DeleteFederatedEntryResponse{}, nil
}

//

func (SqlitePlugin) CreateAttestedNodeEntry(*control_plane_proto.CreateAttestedNodeEntryRequest) (*control_plane_proto.CreateAttestedNodeEntryResponse, error) {
	return &control_plane_proto.CreateAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) FetchAttestedNodeEntry(*control_plane_proto.FetchAttestedNodeEntryRequest) (*control_plane_proto.FetchAttestedNodeEntryResponse, error) {
	return &control_plane_proto.FetchAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) FetchStaleNodeEntries(*control_plane_proto.FetchStaleNodeEntriesRequest) (*control_plane_proto.FetchStaleNodeEntriesResponse, error) {
	return &control_plane_proto.FetchStaleNodeEntriesResponse{}, nil
}

func (SqlitePlugin) UpdateAttestedNodeEntry(*control_plane_proto.UpdateAttestedNodeEntryRequest) (*control_plane_proto.UpdateAttestedNodeEntryResponse, error) {
	return &control_plane_proto.UpdateAttestedNodeEntryResponse{}, nil
}

func (SqlitePlugin) DeleteAttestedNodeEntry(*control_plane_proto.DeleteAttestedNodeEntryRequest) (*control_plane_proto.DeleteAttestedNodeEntryResponse, error) {
	return &control_plane_proto.DeleteAttestedNodeEntryResponse{}, nil
}

//

func (SqlitePlugin) CreateNodeResolverMapEntry(*control_plane_proto.CreateNodeResolverMapEntryRequest) (*control_plane_proto.CreateNodeResolverMapEntryResponse, error) {
	return &control_plane_proto.CreateNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) FetchNodeResolverMapEntry(*control_plane_proto.FetchNodeResolverMapEntryRequest) (*control_plane_proto.FetchNodeResolverMapEntryResponse, error) {
	return &control_plane_proto.FetchNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) DeleteNodeResolverMapEntry(*control_plane_proto.DeleteNodeResolverMapEntryRequest) (*control_plane_proto.DeleteNodeResolverMapEntryResponse, error) {
	return &control_plane_proto.DeleteNodeResolverMapEntryResponse{}, nil
}

func (SqlitePlugin) RectifyNodeResolverMapEntries(*control_plane_proto.RectifyNodeResolverMapEntriesRequest) (*control_plane_proto.RectifyNodeResolverMapEntriesResponse, error) {
	return &control_plane_proto.RectifyNodeResolverMapEntriesResponse{}, nil
}

//

func (SqlitePlugin) CreateRegistrationEntry(*control_plane_proto.CreateRegistrationEntryRequest) (*control_plane_proto.CreateRegistrationEntryResponse, error) {
	return &control_plane_proto.CreateRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) FetchRegistrationEntry(*control_plane_proto.FetchRegistrationEntryRequest) (*control_plane_proto.FetchRegistrationEntryResponse, error) {
	return &control_plane_proto.FetchRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) UpdateRegistrationEntry(*control_plane_proto.UpdateRegistrationEntryRequest) (*control_plane_proto.UpdateRegistrationEntryResponse, error) {
	return &control_plane_proto.UpdateRegistrationEntryResponse{}, nil
}

func (SqlitePlugin) DeleteRegistrationEntry(*control_plane_proto.DeleteRegistrationEntryRequest) (*control_plane_proto.DeleteRegistrationEntryResponse, error) {
	return &control_plane_proto.DeleteRegistrationEntryResponse{}, nil
}

//

func (SqlitePlugin) ListParentIDEntries(*control_plane_proto.ListParentIDEntriesRequest) (*control_plane_proto.ListParentIDEntriesResponse, error) {
	return &control_plane_proto.ListParentIDEntriesResponse{}, nil
}

func (SqlitePlugin) ListSelectorEntries(*control_plane_proto.ListSelectorEntriesRequest) (*control_plane_proto.ListSelectorEntriesResponse, error) {
	return &control_plane_proto.ListSelectorEntriesResponse{}, nil
}

func (SqlitePlugin) ListSpiffeEntries(*control_plane_proto.ListSpiffeEntriesRequest) (*control_plane_proto.ListSpiffeEntriesResponse, error) {
	return &control_plane_proto.ListSpiffeEntriesResponse{}, nil
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
