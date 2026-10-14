package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type (
	EmailBindingRequest struct {
		Email string `json:"email"`
	}
	EmailBindingResponse struct {
		ExpiresAt time.Time `json:"expiresAt"`
	}
)

// @Summary Approve a user's initial email binding
// @Description Requires accounts.email.bind and fresh password plus MFA in SQL. Explicit target UUID, active external-only account without contacts. Sends a code but does not reserve/attach the address, create an account or bypass the owner's MFA. Approval expires no later than the administrator's current authentication proof.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Target user UUID"
// @Param body body EmailBindingRequest true "Email approved for this user"
// @Success 202 {object} EmailBindingResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/email-binding [post]
func (h *EmailBindingHandler) Request(w http.ResponseWriter, r *http.Request) {
	auth, ok := bindingOwner(w, r)
	if !ok {
		return
	}
	var input EmailBindingRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	expires, err := h.service.Request(r.Context(), service.EmailBindingInput{
		Actor:  accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash},
		UserID: domain.UserID(chi.URLParam(r, "id")), Email: input.Email, IP: httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, EmailBindingResponse{ExpiresAt: expires})
}
