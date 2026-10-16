package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type MethodsRequest struct {
	Password *bool `json:"password" binding:"required"`
	EmailOTP *bool `json:"emailOtp" binding:"required"`
	Google   *bool `json:"google" binding:"required"`
	Telegram *bool `json:"telegram" binding:"required"`
} // @name auth_settings_http.MethodsRequest

type RegistrationRequest struct {
	Enabled  *bool `json:"enabled" binding:"required"`
	Google   *bool `json:"google" binding:"required"`
	Telegram *bool `json:"telegram" binding:"required"`
} // @name auth_settings_http.RegistrationRequest

type PolicyRequest struct {
	Methods                   *MethodsRequest          `json:"methods" binding:"required"`
	Registration              *RegistrationRequest     `json:"registration" binding:"required"`
	PasswordEmailVerification domain.EmailVerification `json:"passwordEmailVerification" binding:"required" swaggertype:"string" enums:"disabled,optional,required"`
} // @name auth_settings_http.PolicyRequest

type UpdateRequest struct {
	ExpectedVersion int64          `json:"expectedVersion" binding:"required"`
	Policy          *PolicyRequest `json:"policy" binding:"required"`
} // @name auth_settings_http.UpdateRequest

func (input UpdateRequest) policy() (domain.Policy, bool) {
	if input.Policy == nil || input.Policy.Methods == nil || input.Policy.Registration == nil {
		return domain.Policy{}, false
	}
	methods, registration := input.Policy.Methods, input.Policy.Registration
	if methods.Password == nil || methods.EmailOTP == nil || methods.Google == nil || methods.Telegram == nil ||
		registration.Enabled == nil || registration.Google == nil || registration.Telegram == nil {
		return domain.Policy{}, false
	}
	return domain.Policy{
		Methods:                   domain.PublicMethods{Password: *methods.Password, EmailOTP: *methods.EmailOTP, Google: *methods.Google, Telegram: *methods.Telegram},
		Registration:              domain.PublicRegistration{Enabled: *registration.Enabled, Google: *registration.Google, Telegram: *registration.Telegram},
		PasswordEmailVerification: input.Policy.PasswordEmailVerification,
	}, true
}

// @Summary Replace authentication settings
// @Description Full non-secret policy replacement. Every boolean is required, including false. Requires auth.settings.manage, fresh password and MFA. expectedVersion prevents lost updates; adapters must be ready locally and identically configured on every instance. Existing sessions are not revoked.
// @Tags Auth settings
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body UpdateRequest true "complete policy and current version"
// @Success 200 {object} SettingsResponse
// @Failure 400 {object} httpx.ErrorResponse "invalid_json, invalid_auth_policy"
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "forbidden, fresh_auth_required"
// @Failure 409 {object} httpx.ErrorResponse "auth_policy_conflict, auth_method_not_ready"
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings [post]
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input UpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	policy, ok := input.policy()
	if !ok {
		httpx.Error(w, 400, "invalid_json", "complete policy required")
		return
	}
	snapshot, err := h.service.Update(r.Context(), service.UpdateInput{Actor: actor, ExpectedVersion: input.ExpectedVersion, Policy: policy})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, snapshot)
}
