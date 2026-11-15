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

type ProjectOperationBudgets interface {
	ReadProjectOperationBudgets(context.Context, operators.Principal, domain.DirectoryTarget) (policy.OperationBudgetSettings, error)
	UpdateProjectOperationBudgets(context.Context, operators.Principal, domain.DirectoryTarget, int64, settings.OperationBudgetsPolicy) (policy.OperationBudgetSettings, error)
}

type ProjectOperationBudgetsRequest struct {
	ExpectedVersion int64                            `json:"expectedVersion"`
	Policy          *settings.OperationBudgetsPolicy `json:"policy"`
} // @name project_http.ProjectOperationBudgetsRequest

func (h *AuthPolicyHandler) WithProjectOperationBudgets(backend ProjectOperationBudgets) *AuthPolicyHandler {
	h.operationBudgets = backend
	return h
}

// @Summary Read project operation budget policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.OperationBudgetSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsOperationBudgets
// @Router /api/v1/platform/projects/{id}/auth/settings/operation-budgets [get]
func (h *AuthPolicyHandler) ReadOperationBudgets(w http.ResponseWriter, r *http.Request) {
	h.projectOperationBudgets(w, r, false)
}

// @Summary Update project authentication operation budgets
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectOperationBudgetsRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.OperationBudgetSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsOperationBudgets
// @Router /api/v1/platform/projects/{id}/auth/settings/operation-budgets [post]
func (h *AuthPolicyHandler) UpdateOperationBudgets(w http.ResponseWriter, r *http.Request) {
	h.projectOperationBudgets(w, r, true)
}

func (h *AuthPolicyHandler) projectOperationBudgets(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.operationBudgets == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.OperationBudgetSettings
	var err error
	if update {
		var input ProjectOperationBudgetsRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "operation budget policy required")
			return
		}
		result, err = h.operationBudgets.UpdateProjectOperationBudgets(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.operationBudgets.ReadProjectOperationBudgets(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
