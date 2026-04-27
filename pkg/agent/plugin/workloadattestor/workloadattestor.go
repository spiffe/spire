package workloadattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/types/known/anypb"
)

type WorkloadAttestor interface {
	catalog.PluginInfo

	Attest(ctx context.Context, pid int) ([]*common.Selector, error)
	AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error)
}
