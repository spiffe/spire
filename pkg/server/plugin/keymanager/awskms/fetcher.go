package awskms

import (
	"context"
	"path"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	log         hclog.Logger
	kmsClient   kmsClient
	serverID    string
	trustDomain string
}

func (kf *keyFetcher) fetchKeyEntries(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	paginator := kms.NewListAliasesPaginator(kf.kmsClient, &kms.ListAliasesInput{Limit: aws.Int32(100)})
	g, ctx := errgroup.WithContext(ctx)

	for {
		aliasesResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			return nil, status.Errorf(codes.Internal, "failed to fetch aliases: %v", err)
		case aliasesResp == nil:
			return nil, status.Errorf(codes.Internal, "failed to fetch aliases: nil response")
		}

		kf.log.Debug("Found aliases", "num_aliases", len(aliasesResp.Aliases))

		for _, alias := range aliasesResp.Aliases {
			// Ensure the alias has a name. This check is purely defensive
			// since aliases should always have a name.
			if alias.AliasName == nil {
				continue
			}

			spireKeyID, ok := kf.spireKeyIDFromAlias(*alias.AliasName)
			// ignore aliases/keys not belonging to this server
			if !ok {
				continue
			}

			// The following checks are purely defensive but we want to ensure
			// we don't try and handle an alias with a malformed shape.
			switch {
			case alias.AliasArn == nil:
				return nil, status.Errorf(codes.Internal, "failed to fetch aliases: found SPIRE alias without arn: name=%q", *alias.AliasName)
			case alias.TargetKeyId == nil:
				// this means something external to the plugin created the alias, without associating it to a key.
				// it should never happen with CMKs.
				return nil, status.Errorf(codes.FailedPrecondition, "failed to fetch aliases: found SPIRE alias without key: name=%q arn=%q", *alias.AliasName, *alias.AliasArn)
			}

			a := alias
			// trigger a goroutine to get the details of the key
			g.Go(func() error {
				entry, err := kf.fetchKeyEntryDetails(ctx, a, spireKeyID)
				if err != nil {
					return err
				}

				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	// wait for all the detail gathering routines to finish
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch aliases: %v", statusErr.Message())
	}

	return keyEntries, nil
}

func (kf *keyFetcher) fetchKeyEntryDetails(ctx context.Context, alias types.AliasListEntry, spireKeyID string) (*keyEntry, error) {
	describeResp, err := kf.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to describe key: %v", err)
	case describeResp == nil || describeResp.KeyMetadata == nil:
		return nil, status.Error(codes.Internal, "malformed describe key response")
	case describeResp.KeyMetadata.Arn == nil:
		return nil, status.Errorf(codes.Internal, "found SPIRE alias without key arn: %q", *alias.AliasArn)
	case !describeResp.KeyMetadata.Enabled:
		// this means something external to the plugin, deleted or disabled the key without removing the alias
		// returning an error provides the opportunity or reverting this in KMS
		return nil, status.Errorf(codes.FailedPrecondition, "found disabled SPIRE key: %q, alias: %q", *describeResp.KeyMetadata.Arn, *alias.AliasArn)
	}

	keyType, ok := keyTypeFromKeySpec(describeResp.KeyMetadata.KeySpec)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key spec: %v", describeResp.KeyMetadata.KeySpec)
	}

	publicKeyResp, err := kf.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	case publicKeyResp == nil || publicKeyResp.PublicKey == nil || len(publicKeyResp.PublicKey) == 0:
		return nil, status.Error(codes.Internal, "malformed get public key response")
	}

	return &keyEntry{
		Arn:       *describeResp.KeyMetadata.Arn,
		AliasName: *alias.AliasName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKeyResp.PublicKey,
			Fingerprint: makeFingerprint(publicKeyResp.PublicKey),
		},
	}, nil
}

func (kf *keyFetcher) spireKeyIDFromAlias(aliasName string) (string, bool) {
	trustDomain := sanitizeTrustDomain(kf.trustDomain)
	prefix := path.Join(aliasPrefix, trustDomain, kf.serverID) + "/"
	trimmed := strings.TrimPrefix(aliasName, prefix)
	if trimmed == aliasName {
		return "", false
	}
	return decodeKeyID(trimmed), true
}
