package protoutil

import (
	"reflect"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	AllTrueAgentMask  = MakeAllTrueMask(&types.AgentMask{}).(*types.AgentMask)
	AllTrueBundleMask = MakeAllTrueMask(&types.BundleMask{}).(*types.BundleMask)
	AllTrueEntryMask  = MakeAllTrueMask(&types.EntryMask{}).(*types.EntryMask)

	AllTrueCommonBundleMask = MakeAllTrueMask(&common.BundleMask{}).(*common.BundleMask)
	AllTrueCommonAgentMask  = MakeAllTrueMask(&common.AttestedNodeMask{}).(*common.AttestedNodeMask)
)

func MakeAllTrueMask(m proto.Message) proto.Message {
	v := reflect.ValueOf(proto.Clone(m)).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		ft := t.Field(i)
		fv := v.Field(i)
		// Skip the protobuf internal fields or those that aren't bool's
		if strings.HasPrefix(ft.Name, "XXX_") || ft.Type.Kind() != reflect.Bool {
			continue
		}
		fv.SetBool(true)
	}
	return v.Addr().Interface().(proto.Message)
}
