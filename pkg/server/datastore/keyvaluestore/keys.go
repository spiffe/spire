package keyvaluestore

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TaintX509CA taints an X.509 CA signed using the provided public key
func (ds *DataStore) TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) error {
	existing, err := ds.bundles.Get(ctx, trustDomainID)
	if err != nil {
		return dsErr(err, "datastore-keyvalue")
	}
	updated := existing.Object

	found := false
	for _, eachRootCA := range updated.Bundle.RootCas {
		x509CA, err := x509.ParseCertificate(eachRootCA.DerBytes)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse rootCA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(x509CA.SubjectKeyId)
		if subjectKeyIDToTaint != caSubjectKeyID {
			continue
		}

		if eachRootCA.TaintedKey {
			return status.Errorf(codes.InvalidArgument, "root CA is already tainted")
		}

		found = true
		eachRootCA.TaintedKey = true
	}

	if !found {
		return status.Error(codes.NotFound, "no ca found with provided subject key ID")
	}

	updated.Bundle.SequenceNumber++

	err = ds.bundles.Update(ctx, updated, existing.Metadata.Revision)
	if err != nil {
		return dsErr(err, "TaintX509CA failed to update bundle")
	}

	return nil
}

// RevokeX509CA removes a Root CA from the bundle
func (ds *DataStore) RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) error {
	existing, err := ds.bundles.Get(ctx, trustDomainID)
	if err != nil {
		return dsErr(err, "datastore-keyvalue")
	}
	updated := existing.Object

	keyFound := false
	var rootCAs []*common.Certificate
	for _, ca := range updated.Bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse root CA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		if subjectKeyIDToRevoke == caSubjectKeyID {
			if !ca.TaintedKey {
				return status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted root CA")
			}
			keyFound = true
			continue
		}

		rootCAs = append(rootCAs, ca)
	}

	if !keyFound {
		return status.Error(codes.NotFound, "no root CA found with provided subject key ID")
	}

	updated.Bundle.RootCas = rootCAs
	updated.Bundle.SequenceNumber++

	err = ds.bundles.Update(ctx, updated, existing.Metadata.Revision)
	if err != nil {
		return dsErr(err, "failed to update bundle")
	}

	return nil
}

// TaintJWTKey taints a JWT Authority key
func (ds *DataStore) TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	existing, err := ds.bundles.Get(ctx, trustDomainID)
	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}
	updated := existing.Object

	var taintedKey *common.PublicKey
	for _, jwtKey := range updated.Bundle.JwtSigningKeys {
		if jwtKey.Kid != authorityID {
			continue
		}

		if jwtKey.TaintedKey {
			return nil, status.Error(codes.InvalidArgument, "key is already tainted")
		}

		// Check if a JWT Key with the provided keyID was already
		// tainted in this loop. This is purely defensive since we do not
		// allow to have repeated key IDs.
		if taintedKey != nil {
			return nil, status.Error(codes.Internal, "another JWT Key found with the same KeyID")
		}
		taintedKey = jwtKey
		jwtKey.TaintedKey = true
	}

	if taintedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	updated.Bundle.SequenceNumber++

	err = ds.bundles.Update(ctx, updated, existing.Metadata.Revision)
	if err != nil {
		return nil, dsErr(err, "TaintJWTKey failed to update bundle")
	}

	return taintedKey, nil
}

// RevokeJWTKey removes JWT key from the bundle
func (ds *DataStore) RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	existing, err := ds.bundles.Get(ctx, trustDomainID)
	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}
	updated := existing.Object

	var publicKeys []*common.PublicKey
	var revokedKey *common.PublicKey
	for _, key := range updated.Bundle.JwtSigningKeys {
		if key.Kid == authorityID {
			// Check if a JWT Key with the provided keyID was already
			// found in this loop. This is purely defensive since we do not
			// allow to have repeated key IDs.
			if revokedKey != nil {
				return nil, status.Error(codes.Internal, "another key found with the same KeyID")
			}

			if !key.TaintedKey {
				return nil, status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted key")
			}

			revokedKey = key
			continue
		}
		publicKeys = append(publicKeys, key)
	}
	updated.Bundle.JwtSigningKeys = publicKeys

	if revokedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	updated.Bundle.SequenceNumber++

	err = ds.bundles.Update(ctx, updated, existing.Metadata.Revision)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update bundle: %v", err)
	}

	return revokedKey, nil
}
