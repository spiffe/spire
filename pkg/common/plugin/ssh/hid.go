package ssh

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/url"
	"path"
)

var PluginName = "ssh"

type HostIdentityDocument struct {
	Principal   string
	Certificate []byte
}

type AttestationData struct {
	Document        []byte
	Signature       []byte
	SignatureFormat string
}

func AttestationStepError(step string, cause error) error {
	return fmt.Errorf("Attempted SSH attestation but an error occured %s: %s", step, cause)
}

func SpiffeID(trustDomain, hostname string) *url.URL {
	spiffePath := path.Join("spire", "agent", PluginName, hostname)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   spiffePath,
	}
	return id
}

func NewAttestationBytes(docBytes, sigBytes []byte, sigFormat string) ([]byte, error) {
	data := AttestationData{
		Document:        docBytes,
		Signature:       sigBytes,
		SignatureFormat: sigFormat,
	}

	b, err := gobMarshal(data)
	if err != nil {
		return nil, fmt.Errorf("plugin/ssh: error marshaling attestation data: %v", err)
	}
	return b, nil
}

func AttestationFromBytes(b []byte) (*AttestationData, *HostIdentityDocument, error) {
	var data AttestationData
	if err := gobUnmarshal(b, &data); err != nil {
		return nil, nil, fmt.Errorf("plugin/ssh: error unmarshaling attestation data: %v", err)
	}

	var doc HostIdentityDocument
	if err := gobUnmarshal(data.Document, &doc); err != nil {
		return nil, nil, fmt.Errorf("plugin/ssh: error unmarshaling host identity document: %v", err)
	}

	return &data, &doc, nil
}

func (d HostIdentityDocument) Bytes() ([]byte, error) {
	b, err := gobMarshal(d)
	if err != nil {
		return nil, fmt.Errorf("plugin/ssh: error marshaling host identity document: %v", err)
	}
	return b, nil
}

func gobMarshal(ifc interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(ifc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gobUnmarshal(data []byte, ifc interface{}) error {
	dec := gob.NewDecoder(bytes.NewBuffer(data))
	return dec.Decode(ifc)
}
