//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	SVIDsPath string `hcl:"svids_path"`
}

type Plugin struct {
	svidstorev1.UnimplementedSVIDStoreServer
	configv1.UnimplementedConfigServer

	config *Config
	mtx    sync.RWMutex
	svids  map[string]*svidstorev1.X509SVID
}

func (p *Plugin) DeleteX509SVID(_ context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	secretName, err := getSecretName(req.Metadata)
	if err != nil {
		return nil, err
	}

	err = p.deleteSVID(secretName)
	if err != nil {
		return nil, err
	}

	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

func (p *Plugin) PutX509SVID(_ context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	secretName, err := getSecretName(req.Metadata)
	if err != nil {
		return nil, err
	}

	err = p.putSVID(secretName, req.Svid)
	if err != nil {
		return nil, err
	}

	return &svidstorev1.PutX509SVIDResponse{}, nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.svids = make(map[string]*svidstorev1.X509SVID)

	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	err := os.WriteFile(config.SVIDsPath, []byte("{}"), 0644) //nolint // file used for testing
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write to file: %v", err)
	}

	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) putSVID(secretName string, svid *svidstorev1.X509SVID) error {
	op := func(svids map[string]*svidstorev1.X509SVID) {
		svids[secretName] = svid
	}
	return p.updateFile(op)
}

func (p *Plugin) deleteSVID(secretName string) error {
	op := func(svids map[string]*svidstorev1.X509SVID) {
		delete(svids, secretName)
	}

	return p.updateFile(op)
}

func (p *Plugin) updateFile(op func(map[string]*svidstorev1.X509SVID)) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	op(p.svids)

	data, err := json.Marshal(p.svids)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal json: %s", err.Error())
	}

	err = os.WriteFile(p.config.SVIDsPath, data, 0600)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to write to file: %s", err.Error())
	}

	return nil
}

func getSecretName(metadata []string) (string, error) {
	for _, data := range metadata {
		list := strings.Split(data, "name:")
		if len(list) > 1 {
			return list[1], nil
		}
	}
	return "", status.Error(codes.InvalidArgument, "missing name in metadata")
}

func main() {
	plugin := new(Plugin)

	pluginmain.Serve(
		svidstorev1.SVIDStorePluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
