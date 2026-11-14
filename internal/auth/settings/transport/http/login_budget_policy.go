//nolint:dupl // Concrete request and response types are required by the Swagger generator.
package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type LoginBudgetPolicyDTO struct {
	IPPerMinute                 int `json:"ipPerMinute"`
	IdentityPerMinute           int `json:"identityPerMinute"`
	GlobalPerMinute             int `json:"globalPerMinute"`
	RegistrationIPPerMinute     int `json:"registrationIpPerMinute"`
	RegistrationGlobalPerMinute int `json:"registrationGlobalPerMinute"`
	ResetGlobalPerMinute        int `json:"resetGlobalPerMinute"`
}

type LoginBudgetPolicyView struct {
	Version int64                 `json:"version"`
	Policy  LoginBudgetPolicyDTO  `json:"policy"`
	Source  domain.SourceMetadata `json:"source"`
}

type LoginBudgetPolicyRequest struct {
	ExpectedVersion int64                 `json:"expectedVersion"`
	Policy          *LoginBudgetPolicyDTO `json:"policy"`
}

type LoginBudgetPolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (LoginBudgetPolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, domain.LoginBudgetPolicy) (LoginBudgetPolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone login policy
// @Success 200 {object} LoginBudgetPolicyView
// @Router /api/v1/admin/auth/settings/login-budgets [get]
func (h *LoginBudgetPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[LoginBudgetPolicyView](h.Log, "login_budget_policy", domain.ErrInvalidLoginBudget, "invalid login policy"))
}

// @Summary Change standalone login policy
// @Accept json
// @Param body body LoginBudgetPolicyRequest true "Complete policy and current version"
// @Success 200 {object} LoginBudgetPolicyView
// @Failure 409 {object} PolicyErrorResponse
// @Router /api/v1/admin/auth/settings/login-budgets [post]
func (h *LoginBudgetPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[LoginBudgetPolicyView](h.Log, "login_budget_policy", domain.ErrInvalidLoginBudget, "invalid login policy"))
}
