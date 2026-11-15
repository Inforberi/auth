package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	otp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type EmailOTPPolicyDTO struct {
	TTLSeconds             int64 `json:"ttlSeconds"`
	ResendSeconds          int64 `json:"resendSeconds"`
	RequestsPerMinute      int   `json:"requestsPerMinute"`
	ConfirmationsPerMinute int   `json:"confirmationsPerMinute"`
}

type EmailOTPPolicyView struct {
	Version int64                 `json:"version"`
	Policy  EmailOTPPolicyDTO     `json:"policy"`
	Source  domain.SourceMetadata `json:"source"`
}

type EmailOTPPolicyRequest struct {
	ExpectedVersion int64              `json:"expectedVersion"`
	Policy          *EmailOTPPolicyDTO `json:"policy"`
}

type EmailOTPPolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (EmailOTPPolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, otp.Policy) (EmailOTPPolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone email OTP policy
// @Success 200 {object} EmailOTPPolicyView
// @ID getAdminAuthSettingsEmailOtp
// @Router /api/v1/admin/auth/settings/email-otp [get]
func (h *EmailOTPPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[EmailOTPPolicyView](h.Log, "email_otp_policy", otp.ErrInvalidPolicy, "invalid email OTP policy"))
}

// @Summary Change standalone email OTP policy
// @Accept json
// @Param body body EmailOTPPolicyRequest true "Complete policy and current version"
// @Success 200 {object} EmailOTPPolicyView
// @Failure 409 {object} PolicyErrorResponse
// @ID postAdminAuthSettingsEmailOtp
// @Router /api/v1/admin/auth/settings/email-otp [post]
func (h *EmailOTPPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[EmailOTPPolicyView](h.Log, "email_otp_policy", otp.ErrInvalidPolicy, "invalid email OTP policy"))
}
