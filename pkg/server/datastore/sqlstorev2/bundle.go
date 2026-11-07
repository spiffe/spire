package sqlstorev2

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

// CreateBundle stores the given bundle
func (ds *Plugin) CreateBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = createBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *Plugin) UpdateBundle(ctx context.Context, b *common.Bundle, mask *common.BundleMask) (bundle *common.Bundle, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = updateBundle(tx, b, mask)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *Plugin) SetBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = setBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *Plugin) AppendBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		bundle, err = appendBundle(tx, b)
		return err
	}); err != nil {
		return nil, err
	}
	return bundle, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *Plugin) DeleteBundle(ctx context.Context, trustDomainID string, mode datastore.DeleteMode) (err error) {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = deleteBundle(tx, trustDomainID, mode)
		return err
	})
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *Plugin) FetchBundle(ctx context.Context, trustDomainID string) (resp *common.Bundle, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchBundle(tx, trustDomainID)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// CountBundles can be used to count all existing bundles.
func (ds *Plugin) CountBundles(ctx context.Context) (count int32, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		count, err = countBundles(tx)
		return err
	}); err != nil {
		return 0, err
	}
	return count, nil
}

// ListBundles can be used to fetch all existing bundles.
func (ds *Plugin) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (resp *datastore.ListBundlesResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listBundles(tx, req, ds.DatabaseType())
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// PruneBundle removes expired certs and keys from a bundle
func (ds *Plugin) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		changed, err = pruneBundle(tx, trustDomainID, expiresBefore, ds.log)
		return err
	}); err != nil {
		return false, err
	}

	return changed, nil
}

// TaintX509CAByKey taints an X.509 CA signed using the provided public key
func (ds *Plugin) TaintX509CA(ctx context.Context, trustDoaminID string, subjectKeyIDToTaint string) error {
	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return taintX509CA(tx, trustDoaminID, subjectKeyIDToTaint)
	})
}

// RevokeX509CA removes a Root CA from the bundle
func (ds *Plugin) RevokeX509CA(ctx context.Context, trustDoaminID string, subjectKeyIDToRevoke string) error {
	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		return revokeX509CA(tx, trustDoaminID, subjectKeyIDToRevoke)
	})
}

// TaintJWTKey taints a JWT Authority key
func (ds *Plugin) TaintJWTKey(ctx context.Context, trustDoaminID string, authorityID string) (*common.PublicKey, error) {
	var taintedKey *common.PublicKey
	if err := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		taintedKey, err = taintJWTKey(tx, trustDoaminID, authorityID)
		return err
	}); err != nil {
		return nil, err
	}
	return taintedKey, nil
}

// RevokeJWTAuthority removes JWT key from the bundle
func (ds *Plugin) RevokeJWTKey(ctx context.Context, trustDoaminID string, authorityID string) (*common.PublicKey, error) {
	var revokedKey *common.PublicKey
	if err := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		revokedKey, err = revokeJWTKey(tx, trustDoaminID, authorityID)
		return err
	}); err != nil {
		return nil, err
	}
	return revokedKey, nil
}

func createBundle(tx *gorm.DB, bundle *common.Bundle) (*common.Bundle, error) {
	model, err := bundleToModel(bundle)
	if err != nil {
		return nil, err
	}

	if err := tx.Create(model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return bundle, nil
}

func updateBundle(tx *gorm.DB, newBundle *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	newModel, err := bundleToModel(newBundle)
	if err != nil {
		return nil, err
	}

	model := &Bundle{}
	if err := tx.Where("trust_domain = ?", newModel.TrustDomain).Take(model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	model.Data, newBundle, err = applyBundleMask(model, newBundle, mask)
	if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	if err := tx.Model(model).Select("data", "updated_at").Updates(model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return newBundle, nil
}

func applyBundleMask(model *Bundle, newBundle *common.Bundle, inputMask *common.BundleMask) ([]byte, *common.Bundle, error) {
	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, nil, err
	}

	if inputMask == nil {
		inputMask = protoutil.AllTrueCommonBundleMask
	}

	if inputMask.RefreshHint {
		bundle.RefreshHint = newBundle.RefreshHint
	}

	if inputMask.RootCas {
		bundle.RootCas = newBundle.RootCas
	}

	if inputMask.JwtSigningKeys {
		bundle.JwtSigningKeys = newBundle.JwtSigningKeys
	}

	if inputMask.WitSigningKeys {
		bundle.WitSigningKeys = newBundle.WitSigningKeys
	}

	if inputMask.SequenceNumber {
		bundle.SequenceNumber = newBundle.SequenceNumber
	}

	newModel, err := bundleToModel(bundle)
	if err != nil {
		return nil, nil, err
	}

	return newModel.Data, bundle, nil
}

func setBundle(tx *gorm.DB, b *common.Bundle) (*common.Bundle, error) {
	newModel, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	err = tx.Where("trust_domain = ?", newModel.TrustDomain).Take(model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		bundle, err := createBundle(tx, b)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	} else if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	bundle, err := updateBundle(tx, b, nil)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func appendBundle(tx *gorm.DB, b *common.Bundle) (*common.Bundle, error) {
	newModel, err := bundleToModel(b)
	if err != nil {
		return nil, err
	}

	// fetch existing or create new
	model := &Bundle{}
	err = tx.Where("trust_domain = ?", newModel.TrustDomain).Take(model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		bundle, err := createBundle(tx, b)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	} else if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	// parse the bundle data and add missing elements
	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	bundle, changed := bundleutil.MergeBundles(bundle, b)
	if changed {
		bundle.SequenceNumber++
		newModel, err := bundleToModel(bundle)
		if err != nil {
			return nil, err
		}
		model.Data = newModel.Data
		if err := tx.Model(model).Select("data", "updated_at").Updates(model).Error; err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
	}

	return bundle, nil
}

func deleteBundle(tx *gorm.DB, trustDomainID string, mode datastore.DeleteMode) error {
	model := new(Bundle)
	if err := tx.Where("trust_domain = ?", trustDomainID).Take(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	// Get a count of associated registration entries
	entriesAssociation := tx.Model(model).Association("FederatedEntries")
	entriesCount := entriesAssociation.Count()
	if err := entriesAssociation.Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	// TODO: the branches below are only exercised by the shared suite's
	// TestDeleteBundle*RegistrationEntries tests, which are skipped until
	// registration entries are ported to this datastore.
	if entriesCount > 0 {
		switch mode {
		case datastore.Delete:
			// TODO: figure out how to do this gracefully with GORM.
			if err := tx.Exec(`DELETE FROM registered_entries WHERE id in (
				SELECT
					registered_entry_id
				FROM
					federated_registration_entries
				WHERE
					bundle_id = ?)`, model.ID).Error; err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
		case datastore.Dissociate:
			if err := entriesAssociation.Clear(); err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
		default:
			return status.Newf(codes.FailedPrecondition, "datastore-sql: cannot delete bundle; federated with %d registration entries", entriesCount).Err()
		}
	}

	if err := tx.Delete(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	return nil
}

// fetchBundle returns the bundle matching the specified Trust Domain.
func fetchBundle(tx *gorm.DB, trustDomainID string) (*common.Bundle, error) {
	model := new(Bundle)
	err := tx.Where("trust_domain = ?", trustDomainID).Take(model).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

// countBundles can be used to count existing bundles
func countBundles(tx *gorm.DB) (int32, error) {
	tx = tx.Model(&Bundle{})

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, sqlcommon.NewWrappedSQLError(err)
	}

	return util.CheckedCast[int32](count)
}

// listBundles can be used to fetch all existing bundles.
func listBundles(tx *gorm.DB, req *datastore.ListBundlesRequest, dbType string) (*datastore.ListBundlesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	// Pagination conditions live on query only; tx stays clean for other queries.
	query := tx
	p := req.Pagination
	var err error
	if p != nil {
		query, err = applyPagination(p, tx, dbType)
		if err != nil {
			return nil, err
		}
	}

	var bundles []Bundle
	if err := query.Find(&bundles).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	if p != nil {
		p.Token = ""
		// Set token to the last ID of a non-empty page
		if len(bundles) > 0 {
			lastEntry := bundles[len(bundles)-1]
			p.Token = fmt.Sprint(lastEntry.ID)
		}
	}

	resp := &datastore.ListBundlesResponse{
		Pagination: p,
	}
	for _, model := range bundles {
		bundle, err := modelToBundle(&model)
		if err != nil {
			return nil, err
		}

		resp.Bundles = append(resp.Bundles, bundle)
	}

	return resp, nil
}

func pruneBundle(tx *gorm.DB, trustDomainID string, expiry time.Time, log logrus.FieldLogger) (bool, error) {
	// Get current bundle
	currentBundle, err := fetchBundle(tx, trustDomainID)
	if err != nil {
		return false, fmt.Errorf("unable to fetch current bundle: %w", err)
	}

	if currentBundle == nil {
		// No bundle to prune
		return false, nil
	}

	// Prune
	newBundle, changed, err := bundleutil.PruneBundle(currentBundle, expiry, log)
	if err != nil {
		return false, fmt.Errorf("prune failed: %w", err)
	}

	// Update only if bundle was modified
	if changed {
		newBundle.SequenceNumber = currentBundle.SequenceNumber + 1
		_, err := updateBundle(tx, newBundle, nil)
		if err != nil {
			return false, fmt.Errorf("unable to write new bundle: %w", err)
		}
	}

	return changed, nil
}

func taintX509CA(tx *gorm.DB, trustDomainID string, subjectKeyIDToTaint string) error {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return err
	}

	found := false
	for _, eachRootCA := range bundle.RootCas {
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

	bundle.SequenceNumber++

	_, err = updateBundle(tx, bundle, nil)
	return err
}

func revokeX509CA(tx *gorm.DB, trustDomainID string, subjectKeyIDToRevoke string) error {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return err
	}

	keyFound := false
	var rootCAs []*common.Certificate
	for _, ca := range bundle.RootCas {
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

	bundle.RootCas = rootCAs
	bundle.SequenceNumber++

	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return status.Errorf(codes.Internal, "failed to update bundle: %v", err)
	}

	return nil
}

func taintJWTKey(tx *gorm.DB, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return nil, err
	}

	var taintedKey *common.PublicKey
	for _, jwtKey := range bundle.JwtSigningKeys {
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

	bundle.SequenceNumber++
	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return nil, err
	}

	return taintedKey, nil
}

func revokeJWTKey(tx *gorm.DB, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	bundle, err := getBundle(tx, trustDomainID)
	if err != nil {
		return nil, err
	}

	var publicKeys []*common.PublicKey
	var revokedKey *common.PublicKey
	for _, key := range bundle.JwtSigningKeys {
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
	bundle.JwtSigningKeys = publicKeys

	if revokedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	bundle.SequenceNumber++
	if _, err := updateBundle(tx, bundle, nil); err != nil {
		return nil, err
	}

	return revokedKey, nil
}

func getBundle(tx *gorm.DB, trustDomainID string) (*common.Bundle, error) {
	model := &Bundle{}
	if err := tx.Where("trust_domain = ?", trustDomainID).Take(model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	bundle, err := modelToBundle(model)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal bundle: %v", err)
	}

	return bundle, nil
}

// applyPagination returns a handle with the pagination conditions applied. The
// handle is for exactly one query; further queries must use the original tx.
func applyPagination(p *datastore.Pagination, tx *gorm.DB, dbType string) (*gorm.DB, error) {
	if p.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	tx = tx.Order("id asc").Limit(int(p.PageSize))

	if len(p.Token) > 0 {
		id, err := parsePaginationToken(p.Token, dbType)
		if err != nil {
			return nil, err
		}
		tx = tx.Where("id > ?", id)
	}
	return tx, nil
}

// maxPaginationToken returns the largest ID value the dialect's primary key
// column can represent. Models declare ID as a Go uint, which GORM maps to a
// signed 32-bit integer on PostgreSQL and an unsigned 32-bit integer on
// MySQL, so tokens above those bounds can never match an existing row.
func maxPaginationToken(dbType string) uint64 {
	switch {
	case sqlcommon.IsPostgresDbType(dbType):
		return math.MaxInt32
	case sqlcommon.IsMySQLDbType(dbType):
		return math.MaxUint32
	default:
		return math.MaxUint64
	}
}

// parsePaginationToken parses a pagination token, clamping it to the largest
// value the dialect can compare against. A token beyond every representable
// ID selects no rows, which is the correct result for a page past the end.
func parsePaginationToken(token string, dbType string) (uint64, error) {
	id, err := strconv.ParseUint(token, 10, 64)
	if err != nil {
		return 0, status.Errorf(codes.InvalidArgument, "could not parse token '%v'", token)
	}
	return min(id, maxPaginationToken(dbType)), nil
}

// modelToBundle converts the given bundle model to a Protobuf bundle message.
func modelToBundle(model *Bundle) (*common.Bundle, error) {
	bundle := new(common.Bundle)
	if err := proto.Unmarshal(model.Data, bundle); err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return bundle, nil
}

// bundleToModel converts the given Protobuf bundle message to a database model.
func bundleToModel(pb *common.Bundle) (*Bundle, error) {
	if pb == nil {
		return nil, sqlcommon.NewSQLError("missing bundle in request")
	}
	data, err := proto.Marshal(pb)
	if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return &Bundle{
		TrustDomain: pb.TrustDomainId,
		Data:        data,
	}, nil
}
