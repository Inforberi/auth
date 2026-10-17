package http

import (
	"net/http"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativeEmailRequest struct {
	Email    string                       `json:"email" binding:"required"`
	Audience string                       `json:"audience" binding:"required"`
	Scope    []accessdomain.PermissionKey `json:"scope" binding:"required" swaggertype:"array,string"`
} // @name token_http.NativeEmailRequest

type NativeEmailResponse struct {
	Status    string    `json:"status"`
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name token_http.NativeEmailResponse

// @Summary Request a native email login code
// @Description Native client only, no Origin/Cookie/Authorization/query. Neutral accepted response for unknown or ineligible accounts; code only for eligible existing accounts. Store the returned binding in protected client memory. Audience/scope are bound server-side. No browser flow cookie.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeEmailRequest true "Email and resource scope"
// @Success 202 {object} NativeEmailResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/email/request [post]
func (h *NativeHandler) EmailRequest(w http.ResponseWriter, r *http.Request) {
	var input NativeEmailRequest
	if !decodeNative(w, r, &input, []string{"email", "audience", "scope"}) {
		return
	}
	result, err := h.services.Email.Request(r.Context(), input.Email, httpx.IP(r), input.Audience, input.Scope)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, NativeEmailResponse{Status: "accepted", Binding: result.Binding, ExpiresAt: result.ExpiresAt})
}
