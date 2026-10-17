package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type retentionSettings interface {
	Read(context.Context, accessservice.Principal) (domain.RetentionSnapshot, error)
	Update(context.Context, service.RetentionUpdateInput) (domain.RetentionSnapshot, error)
}

type RetentionHandler struct {
	service retentionSettings
	log     *zap.Logger
}

func NewRetention(service retentionSettings, log *zap.Logger) *RetentionHandler {
	return &RetentionHandler{service: service, log: log}
}

type RetentionPolicyDTO struct {
	EmailReservationDays int `json:"emailReservationDays"`
	SessionDays          int `json:"sessionDays"`
	SecurityAuditDays    int `json:"securityAuditDays"`
} // @name retention_settings_http.Policy

type RetentionResponse struct {
	Version int64              `json:"version"`
	Policy  RetentionPolicyDTO `json:"policy"`
} // @name retention_settings_http.SettingsResponse

func (h *RetentionHandler) respond(w http.ResponseWriter, s domain.RetentionSnapshot) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, RetentionResponse{Version: s.Version, Policy: RetentionPolicyDTO{
		EmailReservationDays: s.Policy.EmailReservationDays, SessionDays: s.Policy.SessionDays, SecurityAuditDays: s.Policy.SecurityAuditDays,
	}})
}

var retentionErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidRetention, 400, "invalid_retention_settings", "retention days must be between 1 and 106751"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "retention_settings_conflict", "retention settings changed; reload and retry"),
	httpx.MatchError(domain.ErrRetentionConfirmation, 409, "retention_confirmation_required", "confirm irreversible cleanup when shortening retention"),
}, settingsErrors...)

func (h *RetentionHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "retention_settings", err, retentionErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
