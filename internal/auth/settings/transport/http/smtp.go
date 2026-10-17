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

type smtpService interface {
	Read(context.Context, accessservice.Principal) (domain.SMTPSnapshot, error)
	Update(context.Context, service.SMTPUpdateInput) (domain.SMTPSnapshot, error)
	TestConnection(context.Context, accessservice.Principal, int64) error
}

type SMTPHandler struct {
	service smtpService
	log     *zap.Logger
}

func NewSMTP(service smtpService, log *zap.Logger) *SMTPHandler {
	return &SMTPHandler{service: service, log: log}
}

type SMTPConfigResponse struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	From       string `json:"from"`
	Domain     string `json:"domain"`
	RequireTLS bool   `json:"requireTls"`
} // @name smtp_settings_http.ConfigResponse

type SMTPResponse struct {
	Version     int64              `json:"version"`
	Config      SMTPConfigResponse `json:"config"`
	PasswordSet bool               `json:"passwordSet"`
} // @name smtp_settings_http.SettingsResponse

func (h *SMTPHandler) respond(w http.ResponseWriter, snapshot domain.SMTPSnapshot) {
	c := snapshot.Config
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, SMTPResponse{
		Version: snapshot.Version, PasswordSet: snapshot.PasswordSet,
		Config: SMTPConfigResponse{Host: c.Host, Port: c.Port, Username: c.Username, From: c.From, Domain: c.Domain, RequireTLS: c.RequireTLS},
	})
}

var smtpErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidSMTP, 400, "invalid_smtp_settings", "invalid SMTP settings or destination"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "smtp_settings_conflict", "SMTP settings changed; reload and retry"),
	httpx.MatchError(service.ErrSMTPTestFailed, 409, "smtp_connection_failed", "SMTP connection test failed"),
	{Target: service.ErrSMTPTestLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, settingsErrors...)

func (h *SMTPHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "smtp_settings", err, smtpErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
