//go:build !windows
// +build !windows

package systemd

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/hashicorp/go-hclog"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	systemdDBusInterface      = "org.freedesktop.systemd1"
	systemdDBusPath           = "/org/freedesktop/systemd1"
	systemdGetUnitByPIDMethod = "org.freedesktop.systemd1.Manager.GetUnitByPID"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
	)
}

type DBusUnitInfo struct {
	UnitID           string
	UnitFragmentPath string
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer

	log hclog.Logger

	// hook for tests
	getUnitInfo func(ctx context.Context, pid uint) (*DBusUnitInfo, error)
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

	selectorValues = append(selectorValues, makeSelectorValue("id", uInfo.UnitID))
	selectorValues = append(selectorValues, makeSelectorValue("fragment_path", uInfo.UnitFragmentPath))

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

func getSystemdUnitInfo(ctx context.Context, pid uint) (*DBusUnitInfo, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open dbus connection: %v", err)
	}
	defer conn.Close()

	// Get the unit for the given PID from the systemd service.
	call := conn.Object(systemdDBusInterface, systemdDBusPath).CallWithContext(ctx, systemdGetUnitByPIDMethod, 0, pid)

	var unitPath dbus.ObjectPath
	err = call.Store(&unitPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get unit by pid %d: %v", pid, err)
	}

	obj := conn.Object(systemdDBusInterface, unitPath)

	id, err := getStringProperty(obj, "Id")
	if err != nil {
		return nil, err
	}
	fragmentPath, err := getStringProperty(obj, "FragmentPath")
	if err != nil {
		return nil, err
	}

	return &DBusUnitInfo{UnitID: id, UnitFragmentPath: fragmentPath}, nil
}

func getStringProperty(obj dbus.BusObject, prop string) (string, error) {
	propVariant, err := obj.GetProperty(systemdDBusInterface + ".Unit." + prop)
	if err != nil {
		return "", status.Errorf(codes.Internal, "error getting value for %s: %v", prop, err)
	}
	propVal, ok := propVariant.Value().(string)
	if !ok {
		return "", status.Errorf(codes.Internal, "Returned value for %v was not a string: %v", prop, propVariant.String())
	}
	return propVal, nil
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}
