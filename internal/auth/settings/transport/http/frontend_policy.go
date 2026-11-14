package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type FrontendPolicyDTO struct {
	Origins                string `json:"origins"`
	CORSEnabled            bool   `json:"corsEnabled"`
	VerificationURL        string `json:"verificationUrl"`
	ResetURL               string `json:"resetUrl"`
	InvitationURL          string `json:"invitationUrl"`
	EmailChangeURL         string `json:"emailChangeUrl"`
	EmailChangeReportURL   string `json:"emailChangeReportUrl"`
	EmailChangeRecoveryURL string `json:"emailChangeRecoveryUrl"`
}

type FrontendPolicyView struct {
	Version int64                 `json:"version"`
	Policy  FrontendPolicyDTO     `json:"policy"`
	Source  domain.SourceMetadata `json:"source"`
}

type FrontendPolicyRequest struct {
	ExpectedVersion int64              `json:"expectedVersion"`
	Policy          *FrontendPolicyDTO `json:"policy"`
}

type FrontendPolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (FrontendPolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, domain.FrontendPolicy) (FrontendPolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone frontend policy
// @Success 200 {object} FrontendPolicyView
// @Router /api/v1/admin/auth/settings/frontend [get]
func (h *FrontendPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[FrontendPolicyView](h.Log, "frontend_policy", domain.ErrInvalidFrontend, "invalid frontend policy"))
}

// @Summary Change standalone frontend policy
// @Accept json
// @Param body body FrontendPolicyRequest true "Complete policy and current version"
// @Success 200 {object} FrontendPolicyView
// @Failure 409 {object} PolicyErrorResponse
// @Router /api/v1/admin/auth/settings/frontend [post]
func (h *FrontendPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[FrontendPolicyView](h.Log, "frontend_policy", domain.ErrInvalidFrontend, "invalid frontend policy"))
}
