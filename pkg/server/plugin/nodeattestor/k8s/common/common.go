package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

type CommonAttestorPlugin struct {
	pluginName string
}

func NewCommonAttestorPlugin(pluginName string) *CommonAttestorPlugin {
	return &CommonAttestorPlugin{
		pluginName: pluginName,
	}
}

func (p *CommonAttestorPlugin) MakeSelector(kind, value string) *common.Selector {
	return &common.Selector{
		Type:  p.pluginName,
		Value: fmt.Sprintf("%s:%s", kind, value),
	}
}

func (p *CommonAttestorPlugin) ValidateAttestReq(req *nodeattestor.AttestRequest) (*k8s.SATAttestationData, error) {
	if req.AttestedBefore {
		return nil, errors.New("node has already attested")
	}

	if req.AttestationData == nil {
		return nil, errors.New("missing attestation data")
	}

	if dataType := req.AttestationData.Type; dataType != p.pluginName {
		return nil, fmt.Errorf("unexpected attestation data type %q", dataType)
	}

	if req.AttestationData.Data == nil {
		return nil, errors.New("missing attestation data payload")
	}

	attestationData := new(k8s.SATAttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return nil, errors.New("missing cluster in attestation data")
	}

	if attestationData.UUID == "" {
		return nil, errors.New("missing UUID in attestation data")
	}

	if attestationData.Token == "" {
		return nil, errors.New("missing token in attestation data")
	}

	return attestationData, nil
}

func (p *CommonAttestorPlugin) ValidateConfigReq(hclConfig interface{}, req *spi.ConfigureRequest) error {
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return fmt.Errorf("unable to decode configuration: %v", err)
	}
	if req.GlobalConfig == nil {
		return errors.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return errors.New("global configuration missing trust domain")
	}

	return nil
}

func (p *CommonAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
