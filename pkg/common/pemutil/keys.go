package pemutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, err := parseBlock(pemBytes, privateKeyType, rsaPrivateKeyType, ecPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return block.Object, nil
}

func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	block, err := loadBlock(path, privateKeyType, rsaPrivateKeyType, ecPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return block.Object, nil
}

func ParseSigner(pemBytes []byte) (crypto.Signer, error) {
	privateKey, err := ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return signerFromPrivateKey(privateKey)
}

func LoadSigner(path string) (crypto.Signer, error) {
	privateKey, err := LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	return signerFromPrivateKey(privateKey)
}

func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, err := parseBlock(pemBytes, privateKeyType, rsaPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return rsaPrivateKeyFromObject(block.Object)
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := loadBlock(path, privateKeyType, rsaPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return rsaPrivateKeyFromObject(block.Object)
}

func rsaPrivateKeyFromObject(object interface{}) (*rsa.PrivateKey, error) {
	key, ok := object.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", key, object)
	}
	return key, nil
}

func ParseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, err := parseBlock(pemBytes, privateKeyType, ecPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return ecdsaPrivateKeyFromObject(block.Object)
}

func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := loadBlock(path, privateKeyType, ecPrivateKeyType)
	if err != nil {
		return nil, err
	}
	return ecdsaPrivateKeyFromObject(block.Object)
}

func EncodePKCS8PrivateKey(privateKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

func ecdsaPrivateKeyFromObject(object interface{}) (*ecdsa.PrivateKey, error) {
	key, ok := object.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", key, object)
	}
	return key, nil
}

func signerFromPrivateKey(privateKey crypto.PrivateKey) (crypto.Signer, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("expected crypto.Signer; got %T", privateKey)
	}
	return signer, nil
}
