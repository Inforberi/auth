package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ConfirmCodeRequest struct {
	Code string `json:"code"`
} // @name emailotp_http.ConfirmCodeRequest

// @Summary Sign in with a one-time email code
// @Description Requires the requesting browser flow cookie, eight decimal digits, allowed Origin, current status/version/email and at most five failed guesses per challenge. One-time consumption then ordinary SQL session issuance; not MFA or password reauthentication.
// @Tags Email OTP
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmCodeRequest true "code"
// @Success 200 {object} StatusResponse
// @Success 202 {object} mfahttp.ChallengeResponse "MFA required; browser binding cookie, no session issued"
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email_login"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email-otp/confirm [post]
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	var input ConfirmCodeRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	binding := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == flowCookie {
			count++
			binding = cookie.Value
		}
	}
	if count != 1 {
		binding = ""
	}
	result, err := h.service.Confirm(r.Context(), service.ConfirmInput{
		Code: input.Code, Binding: binding, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, "", time.Unix(1, 0))
	if result.Challenge != nil {
		mfahttp.RespondChallenge(w, result.Challenge)
		return
	}
	sessionhttp.SetSessionCookie(w, result.RawToken, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
