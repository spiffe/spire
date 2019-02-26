package common

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"gopkg.in/square/go-jose.v2/jwt"
)

// CommonAttestorPlugin encapsulates common functionality for SAT and PSAT node attestors
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

func (p *CommonAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
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

func (p *CommonAttestorPlugin) VerifyTokenSignature(keys []crypto.PublicKey, token *jwt.JSONWebToken, claims interface{}) (err error) {
	var lastErr error
	for _, key := range keys {
		if err := token.Claims(key, claims); err != nil {
			lastErr = fmt.Errorf("unable to verify token: %v", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("token signed by unknown authority")
	}
	return lastErr
}

func (p *CommonAttestorPlugin) LoadServiceAccountKeys(path string) ([]crypto.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keys []crypto.PublicKey
	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return keys, nil
		}
		key, err := decodeKeyBlock(pemBlock)
		if err != nil {
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
}

func decodeKeyBlock(block *pem.Block) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = cert.PublicKey
	case "RSA PUBLIC KEY":
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = rsaKey
	case "PUBLIC KEY":
		pkixKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = pkixKey
	default:
		return nil, nil
	}

	if !isSupportedKey(key) {
		return nil, fmt.Errorf("unsupported %T in %s block", key, block.Type)
	}
	return key, nil
}

func isSupportedKey(key crypto.PublicKey) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return true
	case *ecdsa.PublicKey:
		return true
	default:
		return false
	}
}
