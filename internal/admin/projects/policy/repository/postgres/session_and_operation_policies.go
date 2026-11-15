package postgres

import (
	"context"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type BrowserSessionSettings struct {
	Version int64                   `json:"version"`
	Policy  sessions.BrowserPolicy  `json:"policy"`
	Source  settings.SourceMetadata `json:"source"`
}

func (r *RuntimeAuthPolicy) WithBrowserSessionBaseline(baseline sessions.BrowserPolicy) *RuntimeAuthPolicy {
	r.browserSessions = baseline
	return r
}

type LoginBudgetSettings struct {
	Version int64                      `json:"version"`
	Policy  settings.LoginBudgetPolicy `json:"policy"`
	Source  settings.SourceMetadata    `json:"source"`
}

func (r *RuntimeAuthPolicy) WithLoginBudgetBaseline(baseline settings.LoginBudgetPolicy) *RuntimeAuthPolicy {
	r.loginBudgets = baseline
	return r
}

type OperationBudgetSettings struct {
	Version int64                           `json:"version"`
	Policy  settings.OperationBudgetsPolicy `json:"policy"`
	Source  settings.SourceMetadata         `json:"source"`
}

func (r *RuntimeAuthPolicy) WithOperationBudgetBaseline(baseline settings.OperationBudgetsPolicy) *RuntimeAuthPolicy {
	r.operationBudgets = baseline
	return r
}

func (r *RuntimeAuthPolicy) ReadProjectSessions(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (BrowserSessionSettings, error) {
	return readVersionedSettings(ctx, r, actor, target, settingspg.New(nil).BrowserSessionPolicy(), r.browserSessions, sessionsResponse)
}

func (r *RuntimeAuthPolicy) ReadProjectLoginBudgets(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (LoginBudgetSettings, error) {
	return readVersionedSettings(ctx, r, actor, target, settingspg.New(nil).LoginBudgetPolicy(), r.loginBudgets, loginBudgetResponse)
}

func (r *RuntimeAuthPolicy) ReadProjectOperationBudgets(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (OperationBudgetSettings, error) {
	return readVersionedSettings(ctx, r, actor, target, settingspg.New(nil).OperationBudgetsPolicy(), r.operationBudgets, operationBudgetResponse)
}

func (r *RuntimeAuthPolicy) UpdateProjectOperationBudgets(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy settings.OperationBudgetsPolicy) (OperationBudgetSettings, error) {
	if expected < 1 || policy.Validate(r.operationBudgets) != nil {
		return OperationBudgetSettings{}, settings.ErrInvalidOperationBudgets
	}
	return writeVersionedSettings(ctx, r, actor, target, settingspg.New(nil).OperationBudgetsPolicy(), expected, r.operationBudgets, policy, operationBudgetResponse)
}

func (r *RuntimeAuthPolicy) UpdateProjectLoginBudgets(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy settings.LoginBudgetPolicy) (LoginBudgetSettings, error) {
	if expected < 1 || policy.Validate(r.loginBudgets) != nil {
		return LoginBudgetSettings{}, settings.ErrInvalidLoginBudget
	}
	return writeVersionedSettings(ctx, r, actor, target, settingspg.New(nil).LoginBudgetPolicy(), expected, r.loginBudgets, policy, loginBudgetResponse)
}

func (r *RuntimeAuthPolicy) UpdateProjectSessions(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy sessions.BrowserPolicy) (BrowserSessionSettings, error) {
	if expected < 1 || policy.Validate(r.browserSessions) != nil {
		return BrowserSessionSettings{}, sessions.ErrInvalidBrowserPolicy
	}
	return writeVersionedSettings(ctx, r, actor, target, settingspg.New(nil).BrowserSessionPolicy(), expected, r.browserSessions, policy, sessionsResponse)
}

func sessionsResponse(snapshot settingspg.PolicySnapshot[sessions.BrowserPolicy], mode settings.SourceMode) BrowserSessionSettings {
	return BrowserSessionSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
}

func loginBudgetResponse(snapshot settingspg.PolicySnapshot[settings.LoginBudgetPolicy], mode settings.SourceMode) LoginBudgetSettings {
	return LoginBudgetSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
}

func operationBudgetResponse(snapshot settingspg.PolicySnapshot[settings.OperationBudgetsPolicy], mode settings.SourceMode) OperationBudgetSettings {
	return OperationBudgetSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
}
