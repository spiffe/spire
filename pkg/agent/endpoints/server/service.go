package server

import (
	"context"
	"log"

	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/common/plugin"
)

type ServerService interface {
	Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error)
	PluginInfo(ctx context.Context, request sriplugin.PluginInfoRequest) (response sriplugin.PluginInfoReply, err error)
}

type stubServerService struct {
	ShutdownChannel chan struct{}
	PluginCatalog   *helpers.PluginCatalog
}

type errorStop struct {
	s string
}

func (e *errorStop) Error() string {
	return e.s
}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService(pluginCatalog *helpers.PluginCatalog, shutdownCh chan struct{}) (s *stubServerService) {
	s = &stubServerService{}
	s.PluginCatalog = pluginCatalog
	s.ShutdownChannel = shutdownCh
	return s
}

func (se *stubServerService) Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error) {
	log.Println("Received stop message.")
	defer func() {
		se.ShutdownChannel <- struct{}{}
	}()
	return response, err
}

func (se *stubServerService) PluginInfo(ctx context.Context, request sriplugin.PluginInfoRequest) (response sriplugin.PluginInfoReply, err error) {
	for name, client := range se.PluginCatalog.PluginClientsByName {
		info := &sriplugin.GetPluginInfoResponse{
			Name: name,
			Type: client.Type,
		}
		response.PluginInfo = append(response.PluginInfo, info)
	}
	return response, err
}
