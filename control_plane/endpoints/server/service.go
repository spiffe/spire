package server

import (
	"context"
	"log"
	"time"

	control_plane_proto "github.com/spiffe/sri/control_plane/api/server/proto"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/helpers"
)

type ServerService interface {
	Stop(ctx context.Context, request control_plane_proto.StopRequest) (response control_plane_proto.StopReply, err error)
	PluginInfo(ctx context.Context, request control_plane_proto.PluginInfoRequest) (response control_plane_proto.PluginInfoReply, err error)
}

type stubServerService struct {
	ShutdownChannel chan error
	PluginCatalog   *pluginhelper.PluginCatalog
}

type errorStop struct {
	s string
}

func (e *errorStop) Error() string {
	return e.s
}

//NewService gets a new instance of the service.
func NewService(pluginCatalog *pluginhelper.PluginCatalog, errorChan chan error) (s *stubServerService) {
	s = &stubServerService{}
	s.PluginCatalog = pluginCatalog
	s.ShutdownChannel = errorChan
	return s
}

func (se *stubServerService) Stop(ctx context.Context, request control_plane_proto.StopRequest) (response control_plane_proto.StopReply, err error) {
	log.Println("Received stop message.")
	go func() {
		time.Sleep(2 * time.Second)
		se.ShutdownChannel <- &errorStop{s: "Stopping your server..."}
	}()
	return response, err
}

func (se *stubServerService) PluginInfo(ctx context.Context, request control_plane_proto.PluginInfoRequest) (response control_plane_proto.PluginInfoReply, err error) {
	for _, c := range se.PluginCatalog.PluginConfigs {
		info := &common.GetPluginInfoResponse{
			Name: c.PluginName,
			Type: c.PluginType,
		}
		response.PluginInfo = append(response.PluginInfo, info)
	}
	return response, err
}