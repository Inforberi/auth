package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type OperationBudgetsPolicyDTO struct {
	GoogleIP         int `json:"googleIPPerMinute"`
	GoogleGlobal     int `json:"googleGlobalPerMinute"`
	TelegramIP       int `json:"telegramIPPerMinute"`
	TelegramGlobal   int `json:"telegramGlobalPerMinute"`
	MFAUser          int `json:"mfaUserPerMinute"`
	MFAIP            int `json:"mfaIPPerMinute"`
	MFAGlobal        int `json:"mfaGlobalPerMinute"`
	BindingRequest   int `json:"bindingRequestPerMinute"`
	BindingConfirm   int `json:"bindingConfirmPerMinute"`
	InvitationActor  int `json:"invitationActorPerMinute"`
	InvitationGlobal int `json:"invitationGlobalPerMinute"`
	ActivationGlobal int `json:"activationGlobalPerMinute"`
	TemporaryActor   int `json:"temporaryActorPerMinute"`
	TemporaryGlobal  int `json:"temporaryGlobalPerMinute"`
	TemporarySetup   int `json:"temporarySetupPerMinute"`
	JWTActor         int `json:"jwtActorPerMinute"`
	JWTSession       int `json:"jwtSessionPerMinute"`
	JWTIP            int `json:"jwtIPPerMinute"`
	JWTGlobal        int `json:"jwtGlobalPerMinute"`
	JWTConsumer      int `json:"jwtConsumerPerMinute"`
	JWTIntrospection int `json:"jwtIntrospectionPerMinute"`
}

type OperationBudgetsPolicyView struct {
	Version int64                     `json:"version"`
	Policy  OperationBudgetsPolicyDTO `json:"policy"`
	Source  domain.SourceMetadata     `json:"source"`
}

type OperationBudgetsPolicyRequest struct {
	ExpectedVersion int64                      `json:"expectedVersion"`
	Policy          *OperationBudgetsPolicyDTO `json:"policy"`
}

type OperationBudgetsPolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (OperationBudgetsPolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, domain.OperationBudgetsPolicy) (OperationBudgetsPolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone login policy
// @Success 200 {object} OperationBudgetsPolicyView
// @Router /api/v1/admin/auth/settings/operation-budgets [get]
func (h *OperationBudgetsPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[OperationBudgetsPolicyView](h.Log, "operation_budgets_policy", domain.ErrInvalidOperationBudgets, "invalid operation budgets"))
}

// @Summary Change standalone login policy
// @Accept json
// @Param body body OperationBudgetsPolicyRequest true "Complete policy and current version"
// @Success 200 {object} OperationBudgetsPolicyView
// @Failure 409 {object} PolicyErrorResponse
// @Router /api/v1/admin/auth/settings/operation-budgets [post]
func (h *OperationBudgetsPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[OperationBudgetsPolicyView](h.Log, "operation_budgets_policy", domain.ErrInvalidOperationBudgets, "invalid operation budgets"))
}
