package server

import (
	"context"
	"log"
	"time"

	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/common/plugin"
)

type ServerService interface {
	Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error)
	PluginInfo(ctx context.Context, request sriplugin.PluginInfoRequest) (response sriplugin.PluginInfoReply, err error)
}

type stubServerService struct {
	ShutdownChannel chan error
	PluginCatalog   *helpers.PluginCatalog
}

type errorStop struct {
	s string
}

func (e *errorStop) Error() string {
	return e.s
}

//NewService gets a new instance of the service.
func NewService(pluginCatalog *helpers.PluginCatalog, errorChan chan error) (s *stubServerService) {
	s = &stubServerService{}
	s.PluginCatalog = pluginCatalog
	s.ShutdownChannel = errorChan
	return s
}

func (se *stubServerService) Stop(ctx context.Context, request sriplugin.StopRequest) (response sriplugin.StopReply, err error) {
	log.Println("Received stop message.")
	go func() {
		time.Sleep(2 * time.Second)
		se.ShutdownChannel <- &errorStop{s: "Stopping your server..."}
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
