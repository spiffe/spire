//go:build !windows
// +build !windows

package systemd

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/godbus/dbus/v5"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
	)
}

type unitInfo interface {
	Id() (string, error)
	FragmentPath() (string, error)
}

type DBusUnitObject struct {
	dbus.BusObject
}

func getStringProperty(obj DBusUnitObject, prop string) (string, error) {
	propVariant, err := obj.GetProperty("org.freedesktop.systemd1.Unit." + prop)
	if err != nil {
		return "", err
	}
	propVal, ok := propVariant.Value().(string)
	if !ok {
		return "", fmt.Errorf("Returned value for %v was not a string: %v", prop, propVariant.String())
	}
	return propVal, nil
}

func (obj DBusUnitObject) Id() (string, error) {
	return getStringProperty(obj, "Id")
}

func (obj DBusUnitObject) FragmentPath() (string, error) {
	return getStringProperty(obj, "FragmentPath")
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer

	log    hclog.Logger

	// hook for tests
	getUnitInfo func(ctx context.Context, pid uint) (unitInfo, error)
}

func getSystemdUnitInfo(ctx context.Context, pid uint) (unitInfo, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	// Get the unit for the given PID from the systemd service.
	call := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnitByPID", 0, pid)

	var unitPath dbus.ObjectPath
	err = call.Store(&unitPath)
	if err != nil {
		return nil, err
	}

	obj := conn.Object("org.freedesktop.systemd1", unitPath)
	return DBusUnitObject{obj}, nil
}

func New() *Plugin {
	p := &Plugin{}
	p.getUnitInfo = getSystemdUnitInfo
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	uInfo, err := p.getUnitInfo(ctx, uint(req.Pid))
	if err != nil {
		return nil, err
	}

	var selectorValues []string

	unitId, err := uInfo.Id()
	if err != nil {
		return nil, err
	}
	selectorValues = append(selectorValues, makeSelectorValue("Id", unitId))

	fragmentPath, err := uInfo.FragmentPath()
	if err != nil {
		return nil, err
	}
	selectorValues = append(selectorValues, makeSelectorValue("FragmentPath", fragmentPath))

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}
