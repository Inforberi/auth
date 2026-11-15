package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policy "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectLoginBudgets interface {
	ReadProjectLoginBudgets(context.Context, operators.Principal, domain.DirectoryTarget) (policy.LoginBudgetSettings, error)
	UpdateProjectLoginBudgets(context.Context, operators.Principal, domain.DirectoryTarget, int64, settings.LoginBudgetPolicy) (policy.LoginBudgetSettings, error)
}

type ProjectLoginBudgetsRequest struct {
	ExpectedVersion int64                       `json:"expectedVersion"`
	Policy          *settings.LoginBudgetPolicy `json:"policy"`
} // @name project_http.ProjectLoginBudgetsRequest

func (h *AuthPolicyHandler) WithProjectLoginBudgets(backend ProjectLoginBudgets) *AuthPolicyHandler {
	h.loginBudgets = backend
	return h
}

// @Summary Read project login budget policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.LoginBudgetSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsLoginBudgets
// @Router /api/v1/platform/projects/{id}/auth/settings/login-budgets [get]
func (h *AuthPolicyHandler) ReadLoginBudgets(w http.ResponseWriter, r *http.Request) {
	h.projectLoginBudgets(w, r, false)
}

// @Summary Update project password login, registration and reset budgets
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectLoginBudgetsRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.LoginBudgetSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsLoginBudgets
// @Router /api/v1/platform/projects/{id}/auth/settings/login-budgets [post]
func (h *AuthPolicyHandler) UpdateLoginBudgets(w http.ResponseWriter, r *http.Request) {
	h.projectLoginBudgets(w, r, true)
}

func (h *AuthPolicyHandler) projectLoginBudgets(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.loginBudgets == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.LoginBudgetSettings
	var err error
	if update {
		var input ProjectLoginBudgetsRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "login budget policy required")
			return
		}
		result, err = h.loginBudgets.UpdateProjectLoginBudgets(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.loginBudgets.ReadProjectLoginBudgets(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
