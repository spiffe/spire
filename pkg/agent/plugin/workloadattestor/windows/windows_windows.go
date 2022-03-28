//go:build windows
// +build windows

package windows

import (
	"context"
	"fmt"
	"syscall"

	"github.com/hashicorp/go-hclog"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName, workloadattestorv1.WorkloadAttestorPluginServer(p))
}

func New() *Plugin {
	p := &Plugin{q: &processQuery{}}
	return p
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer

	log hclog.Logger
	q   processQueryer
}

type process struct {
	pid int32

	user       string
	userSID    string
	groups     []string
	groupsSIDs []string
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	process, err := p.newProcess(req.Pid, p.q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process information: %v", err)
	}
	var selectorValues []string
	selectorValues = addSelectorValueIfNotEmpty(selectorValues, "user", process.user)
	selectorValues = addSelectorValueIfNotEmpty(selectorValues, "user_sid", process.userSID)
	for _, groupSID := range process.groupsSIDs {
		selectorValues = addSelectorValueIfNotEmpty(selectorValues, "group_sid", groupSID)
	}
	for _, group := range process.groups {
		selectorValues = addSelectorValueIfNotEmpty(selectorValues, "group", group)
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) newProcess(pid int32, q processQueryer) (*process, error) {
	h, err := q.OpenProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(h); err != nil {
			p.log.Warn("Could not close process handle", telemetry.Error, err)
		}
	}()
	var token windows.Token
	err = q.OpenProcessToken(h, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to open the access token associated with the process: %w", err)
	}
	defer token.Close()

	tokenUser, err := q.GetTokenUser(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user account information from access token: %w", err)
	}

	process := &process{pid: pid}
	process.userSID = tokenUser.User.Sid.String()
	account, domain, err := q.LookupAccount(tokenUser.User.Sid)
	if err != nil {
		p.log.Warn("failed to lookup account from user SID", "sid", tokenUser.User.Sid, "error", err)
	} else {
		process.user = domain + "\\" + account
	}

	tokenGroups, err := q.GetTokenGroups(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve group accounts information from access token: %w", err)
	}
	groups := q.AllGroups(tokenGroups)
	for _, group := range groups {
		process.groupsSIDs = append(process.groupsSIDs, group.Sid.String())
		account, domain, err := q.LookupAccount(group.Sid)
		if err != nil {
			p.log.Warn("failed to lookup account from group SID", "sid", group.Sid, "error", err)
			continue
		}
		process.groups = append(process.groups, domain+"\\"+account)
	}

	return process, nil
}

type processQueryer interface {
	OpenProcess(int32) (windows.Handle, error)
	OpenProcessToken(windows.Handle, *windows.Token) error
	LookupAccount(sid *windows.SID) (account, domain string, err error)
	GetTokenUser(*windows.Token) (*windows.Tokenuser, error)
	GetTokenGroups(*windows.Token) (*windows.Tokengroups, error)
	AllGroups(*windows.Tokengroups) []windows.SIDAndAttributes
}

type processQuery struct{}

func (q *processQuery) OpenProcess(pid int32) (handle windows.Handle, err error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

func (q *processQuery) OpenProcessToken(h windows.Handle, token *windows.Token) (err error) {
	return windows.OpenProcessToken(h, syscall.TOKEN_QUERY, token)
}

func (q *processQuery) LookupAccount(sid *windows.SID) (account, domain string, err error) {
	account, domain, _, err = sid.LookupAccount("")
	return account, domain, err
}

func (q *processQuery) GetTokenUser(t *windows.Token) (*windows.Tokenuser, error) {
	return t.GetTokenUser()
}

func (q *processQuery) GetTokenGroups(t *windows.Token) (*windows.Tokengroups, error) {
	return t.GetTokenGroups()
}

func (q *processQuery) AllGroups(t *windows.Tokengroups) []windows.SIDAndAttributes {
	return t.AllGroups()
}

func addSelectorValueIfNotEmpty(selectorValues []string, kind, value string) []string {
	if value != "" {
		return append(selectorValues, fmt.Sprintf("%s:%s", kind, value))
	}
	return selectorValues
}
