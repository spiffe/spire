#!/bin/sh

set -e

sed -i.bak -e 's#"github.com/spiffe/spire/pkg/common/catalog"#catalog "github.com/spiffe/spire/pkg/common/catalog/internal"#g' *.go
rm -f *.bak
