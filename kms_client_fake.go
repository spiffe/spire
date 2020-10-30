package kms

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/require"
)

const (
	signVerifyKeyUsage string = "SIGN_VERIFY"
)

type kmsClientFake struct {
	t *testing.T

	expectedCreateKeyInput *kms.CreateKeyInput
	createKeyOutput        *kms.CreateKeyOutput

	expectedDescribeKeyInput *kms.DescribeKeyInput
	describeKeyOutput        *kms.DescribeKeyOutput

	expectedGetPublicKeyInput *kms.GetPublicKeyInput
	getPublicKeyOutput        *kms.GetPublicKeyOutput

	expectedListKeysInput *kms.ListKeysInput
	listKeysOutput        *kms.ListKeysOutput

	expectedScheduleKeyDeletionInput *kms.ScheduleKeyDeletionInput
	scheduleKeyDeletionOutput        *kms.ScheduleKeyDeletionOutput

	expectedSignInput *kms.SignInput
	signOutput        *kms.SignOutput

	err error
}

func (k *kmsClientFake) CreateKeyWithContext(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error) {
	require.Equal(k.t, k.expectedCreateKeyInput, input)
	if k.err != nil {
		return nil, k.err
	}
	return k.createKeyOutput, nil
}

func (k *kmsClientFake) DescribeKeyWithContext(ctx aws.Context, input *kms.DescribeKeyInput, opts ...request.Option) (*kms.DescribeKeyOutput, error) {
	require.Equal(k.t, k.expectedDescribeKeyInput, input)
	if k.err != nil {
		return nil, k.err
	}

	return k.describeKeyOutput, nil
}

func (k *kmsClientFake) GetPublicKeyWithContext(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
	require.Equal(k.t, k.expectedGetPublicKeyInput, input)
	if k.err != nil {
		return nil, k.err
	}

	return k.getPublicKeyOutput, nil
}

func (k *kmsClientFake) ListKeysWithContext(ctx aws.Context, input *kms.ListKeysInput, opts ...request.Option) (*kms.ListKeysOutput, error) {
	require.Equal(k.t, k.expectedListKeysInput, input)
	if k.err != nil {
		return nil, k.err
	}

	return k.listKeysOutput, nil
}

func (k *kmsClientFake) ScheduleKeyDeletionWithContext(ctx aws.Context, input *kms.ScheduleKeyDeletionInput, opts ...request.Option) (*kms.ScheduleKeyDeletionOutput, error) {
	require.Equal(k.t, k.expectedScheduleKeyDeletionInput, input)
	if k.err != nil {
		return nil, k.err
	}

	return k.scheduleKeyDeletionOutput, nil
}

func (k *kmsClientFake) SignWithContext(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error) {
	require.Equal(k.t, k.expectedSignInput, input)
	if k.err != nil {
		return nil, k.err
	}

	return k.signOutput, nil
}

func (k *kmsClientFake) CreateAliasWithContext(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error) {
	return nil, nil
}
