package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	SVIDsPath string `hcl:"svids_path"`
}

type Plugin struct {
	svidstorev1.UnimplementedSVIDStoreServer
	configv1.UnimplementedConfigServer

	mtx   sync.RWMutex
	file  *os.File
	svids map[string]*svidstorev1.X509SVID
}

func (p *Plugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
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

func (p *Plugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
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

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	var file *os.File

	file, err := os.OpenFile(config.SVIDsPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprint("failed to open file: ", err))
	}

	_, err = file.Write([]byte("{}"))
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprint("failed to write to file: ", err))
	}

	p.file = file
	p.svids = make(map[string]*svidstorev1.X509SVID)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Close() error {
	return p.file.Close()
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
		return status.Error(codes.Internal, fmt.Sprint("failed to marshal json: ", err))
	}
	err = p.file.Truncate(0)
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprint("failed to truncate file: ", err))
	}
	_, err = p.file.Seek(0, 0)
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprint("failed to reset file offset: ", err))
	}
	n, err := p.file.Write(data)
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprint("failed to write to file: ", err))
	}
	if n != len(data) {
		return status.Error(codes.Internal, "failed to write all required data to to file")
	}
	return nil
}

func getSecretName(metadata []string) (string, error) {
	parsedMetadata, err := svidstore.ParseMetadata(metadata)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, fmt.Sprintf("failed to parse metadata: %v", err))
	}
	secretName, ok := parsedMetadata["name"]
	if !ok {
		return "", status.Error(codes.InvalidArgument, "missing name in metadata")
	}

	return secretName, nil
}

func main() {
	plugin := new(Plugin)

	pluginmain.Serve(
		svidstorev1.SVIDStorePluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
