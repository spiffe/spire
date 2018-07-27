package pemutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

var (
	ErrNoBlocks = errors.New("no PEM blocks")
)

type Block struct {
	Type    string
	Headers map[string]string
	Object  interface{}
}

func LoadBlocks(path string) ([]Block, error) {
	return loadBlocks(path, 0, "")
}

func loadBlock(path string, expectedTypes ...string) (*Block, error) {
	blocks, err := loadBlocks(path, 1, expectedTypes...)
	if err != nil {
		return nil, err
	}
	return &blocks[0], nil
}

func loadBlocks(path string, expectedCount int, expectedTypes ...string) (blocks []Block, err error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseBlocks(pemBytes, expectedCount, expectedTypes...)
}

func ParseBlocks(pemBytes []byte) ([]Block, error) {
	return parseBlocks(pemBytes, 0, "")
}

func parseBlock(pemBytes []byte, expectedTypes ...string) (*Block, error) {
	blocks, err := parseBlocks(pemBytes, 1, expectedTypes...)
	if err != nil {
		return nil, err
	}
	return &blocks[0], nil
}

func parseBlocks(pemBytes []byte, expectedCount int, expectedTypes ...string) (blocks []Block, err error) {
	for blockno := 1; ; blockno++ {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			if len(blocks) == 0 {
				return nil, ErrNoBlocks
			}
			if expectedCount > 0 && len(blocks) > expectedCount {
				return nil, fmt.Errorf("expected %d PEM blocks; got %d", expectedCount, len(blocks))
			}
			return blocks, nil
		}

		block := Block{
			Type:    pemBlock.Type,
			Headers: pemBlock.Headers,
		}

		if len(expectedTypes) > 0 {
			found := false
			for _, expectedType := range expectedTypes {
				if expectedType == pemBlock.Type {
					found = true
					break
				}
			}
			if !found {
				var expectedTypeList interface{} = expectedTypes
				if len(expectedTypes) == 1 {
					expectedTypeList = expectedTypes[0]
				}
				return nil, fmt.Errorf("expected block type %q; got %q", expectedTypeList, pemBlock.Type)
			}
		}

		switch pemBlock.Type {
		case "CERTIFICATE":
			block.Object, err = x509.ParseCertificate(pemBlock.Bytes)
		case "CERTIFICATE REQUEST":
			block.Object, err = x509.ParseCertificateRequest(pemBlock.Bytes)
		case "RSA PRIVATE KEY":
			block.Object, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		case "EC PRIVATE KEY":
			block.Object, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		case "PRIVATE KEY":
			block.Object, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("unable to parse %q PEM block %d: %v", pemBlock.Type, blockno, err)
		}

		blocks = append(blocks, block)
	}
}
