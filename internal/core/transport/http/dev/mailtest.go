package dev

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"go.uber.org/zap"
)

type MailSender interface {
	Send(to, subject, body string) error
}

type MailTestHandler struct {
	mail MailSender
	log  *zap.Logger
}

func NewMailTest(mail MailSender, log *zap.Logger) *MailTestHandler {
	return &MailTestHandler{
		mail: mail,
		log:  log.With(zap.String("feature", "dev"), zap.String("handler", "mail_test")),
	}
}

type SendMailRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type SendMailResponse struct {
	Status string `json:"status" example:"ok"`
}

// @Summary Send test email
// @Description Dev-only endpoint for manual SMTP testing. Available only when APP_ENV=dev.
// @Tags Dev
// @Accept json
// @Produce json
// @Param body body SendMailRequest true "mail payload"
// @Success 200 {object} SendMailResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, to_required, subject_required, body_required"
// @Failure 500 {object} httpx.ErrorResponse "code: send_failed"
// @Router /dev/send-mail [post]
func (h *MailTestHandler) Send(w http.ResponseWriter, r *http.Request) {
	var input SendMailRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_json", "invalid json")
		return
	}

	if input.To == "" {
		httpx.Error(w, http.StatusBadRequest, "to_required", "to required")
		return
	}
	if input.Subject == "" {
		httpx.Error(w, http.StatusBadRequest, "subject_required", "subject required")
		return
	}
	if input.Body == "" {
		httpx.Error(w, http.StatusBadRequest, "body_required", "body required")
		return
	}

	if err := h.mail.Send(input.To, input.Subject, input.Body); err != nil {
		h.log.Error("send mail failed", zap.Error(err), zap.String("to", input.To))
		httpx.Error(w, http.StatusInternalServerError, "send_failed", "send failed")
		return
	}

	httpx.JSON(w, http.StatusOK, SendMailResponse{Status: "ok"})
}
