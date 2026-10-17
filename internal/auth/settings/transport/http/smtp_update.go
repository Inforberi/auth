package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SMTPConfigRequest struct {
	Host       string `json:"host" binding:"required"`
	Port       int    `json:"port" binding:"required"`
	Username   string `json:"username"`
	From       string `json:"from" binding:"required"`
	Domain     string `json:"domain" binding:"required"`
	RequireTLS *bool  `json:"requireTls" binding:"required"`
} // @name smtp_settings_http.ConfigRequest

type SMTPUpdateRequest struct {
	ExpectedVersion int64              `json:"expectedVersion" binding:"required"`
	Config          *SMTPConfigRequest `json:"config" binding:"required"`
	Password        *string            `json:"password" extensions:"x-nullable"`
} // @name smtp_settings_http.UpdateRequest

// @Summary Replace SMTP settings and optionally rotate the password
// @Description Requires auth.settings.manage and fresh password+MFA. Full config replacement, explicit requireTls. Omitted/null password preserves it; empty clears it only without username. Changed destination/username requires explicit password. SMTP_ALLOWED_TARGETS is deployment-only; production cannot disable TLS. No network request in this transaction.
// @Tags SMTP settings
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body SMTPUpdateRequest true "configuration, expectedVersion and optional password"
// @Success 200 {object} SMTPResponse
// @Failure 400 {object} httpx.ErrorResponse "invalid_json, invalid_smtp_settings"
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "forbidden, fresh_auth_required"
// @Failure 409 {object} httpx.ErrorResponse "smtp_settings_conflict"
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/smtp [post]
func (h *SMTPHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input SMTPUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Config == nil || input.Config.RequireTLS == nil {
		httpx.Error(w, 400, "invalid_json", "complete SMTP configuration required")
		return
	}
	c := input.Config
	result, err := h.service.Update(r.Context(), service.SMTPUpdateInput{
		Actor: actor, ExpectedVersion: input.ExpectedVersion,
		Config: domain.SMTPConfig{Host: c.Host, Port: c.Port, Username: c.Username, From: c.From, Domain: c.Domain, RequireTLS: *c.RequireTLS}, Password: input.Password,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
