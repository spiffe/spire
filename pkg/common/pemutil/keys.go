package pemutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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

func ecdsaPrivateKeyFromObject(object interface{}) (*ecdsa.PrivateKey, error) {
	key, ok := object.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", key, object)
	}
	return key, nil
}
