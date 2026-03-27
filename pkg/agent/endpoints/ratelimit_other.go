//go:build !linux

package endpoints

import "github.com/sirupsen/logrus"

func newPodUIDResolver(_ logrus.FieldLogger) podUIDResolver { return nil }
