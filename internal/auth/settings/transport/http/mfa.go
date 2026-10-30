package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type mfaSettings interface {
	Read(context.Context, accessservice.Principal) (domain.MFASnapshot, error)
	Update(context.Context, service.MFAUpdateInput) (domain.MFASnapshot, error)
}

type MFAHandler struct {
	service mfaSettings
	log     *zap.Logger
	rules   []httpx.ErrorRule
}

func NewMFA(service mfaSettings, log *zap.Logger, realmErrors ...httpx.ErrorRule) *MFAHandler {
	rules := append([]httpx.ErrorRule(nil), realmErrors...)
	rules = append(rules,
		httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh primary proof and required MFA needed"),
		httpx.MatchError(domain.ErrInvalidMFAPolicy, 400, "invalid_mfa_policy", "valid MFA mode and positive expectedVersion required"),
		httpx.MatchError(domain.ErrPolicyConflict, 409, "mfa_policy_conflict", "MFA policy changed; reload and retry"),
		httpx.MatchError(domain.ErrMethodNotReady, 409, "mfa_not_ready", "MFA capability unavailable"),
	)
	rules = append(rules, settingsErrors...)
	return &MFAHandler{service: service, log: log, rules: rules}
}

type MFAPolicyDTO struct {
	Mode domain.MFAMode `json:"mode" swaggertype:"string" enums:"optional,administrators,required"`
} // @name mfa_settings_http.Policy

type MFASettingsResponse struct {
	Version int64        `json:"version"`
	Policy  MFAPolicyDTO `json:"policy"`
} // @name mfa_settings_http.SettingsResponse

func (h *MFAHandler) respond(w http.ResponseWriter, snapshot domain.MFASnapshot) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, MFASettingsResponse{Version: snapshot.Version, Policy: MFAPolicyDTO{Mode: snapshot.Policy.Mode}})
}

func (h *MFAHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "mfa_settings", err, h.rules,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
