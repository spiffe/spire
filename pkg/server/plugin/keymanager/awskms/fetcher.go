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
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
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
		if err != nil {
			return nil, newErrorf(codes.Internal, "failed to fetch aliases: %v", err)
		}
		kf.log.Debug("Found aliases", "num_aliases", len(aliasesResp.Aliases))

		for _, alias := range aliasesResp.Aliases {
			switch {
			case alias.TargetKeyId == nil:
				// this means something external to the plugin created the alias, without associating it to a key.
				// it should never happen with CMKs.
				return nil, newErrorf(codes.FailedPrecondition, "failed to fetch aliases: found SPIRE alias without key: %q", *alias.AliasArn)
			case alias.AliasArn == nil:
				return nil, newErrorf(codes.Internal, "failed to fetch aliases: found SPIRE alias without arn: %q", *alias.AliasArn)
			case alias.AliasName == nil:
				return nil, newError(codes.Internal, "failed to fetch aliases: found alias without a name")
			}

			spireKeyID, ok := kf.spireKeyIDFromAlias(*alias.AliasName)
			// ignore aliases/keys not belonging to this server
			if !ok {
				continue
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
		return nil, newErrorf(statusErr.Code(), "failed to fetch aliases: %v", statusErr.Message())
	}

	return keyEntries, nil
}

func (kf *keyFetcher) fetchKeyEntryDetails(ctx context.Context, alias types.AliasListEntry, spireKeyID string) (*keyEntry, error) {
	describeResp, err := kf.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, newErrorf(codes.Internal, "failed to describe key: %v", err)
	case describeResp == nil || describeResp.KeyMetadata == nil:
		return nil, newError(codes.Internal, "malformed describe key response")
	case describeResp.KeyMetadata.Arn == nil:
		return nil, newErrorf(codes.Internal, "found SPIRE alias without key arn: %q", *alias.AliasArn)
	case !describeResp.KeyMetadata.Enabled:
		// this means something external to the plugin, deleted or disabled the key without removing the alias
		// returning an error provides the opportunity or reverting this in KMS
		return nil, newErrorf(codes.FailedPrecondition, "found disabled SPIRE key: %q, alias: %q", *describeResp.KeyMetadata.Arn, *alias.AliasArn)
	}

	keyType, ok := keyTypeFromKeySpec(describeResp.KeyMetadata.CustomerMasterKeySpec)
	if !ok {
		return nil, newErrorf(codes.Internal, "unsupported key spec: %v", describeResp.KeyMetadata.CustomerMasterKeySpec)
	}

	publicKeyResp, err := kf.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: alias.AliasArn})
	switch {
	case err != nil:
		return nil, newErrorf(codes.Internal, "failed to get public key: %v", err)
	case publicKeyResp == nil || publicKeyResp.PublicKey == nil || len(publicKeyResp.PublicKey) == 0:
		return nil, newError(codes.Internal, "malformed get public key response")
	}

	return &keyEntry{
		Arn:       *describeResp.KeyMetadata.Arn,
		AliasName: *alias.AliasName,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: publicKeyResp.PublicKey,
		},
	}, nil
}

func (kf *keyFetcher) spireKeyIDFromAlias(aliasName string) (string, bool) {
	trustDomain := sanitizeTrustDomain(kf.trustDomain)
	prefix := path.Join(aliasPrefix, trustDomain, kf.serverID) + "/"
	if !strings.HasPrefix(aliasName, prefix) {
		return "", false
	}
	return strings.TrimPrefix(aliasName, prefix), true
}
