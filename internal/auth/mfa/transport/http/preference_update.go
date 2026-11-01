package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PreferenceRequest struct {
	ExpectedVersion *int64         `json:"expectedVersion"`
	Method          *domain.Method `json:"method"`
}

// @Summary Select an enrolled, allowed MFA method
// @Description Empty method selects auto. Fresh proofs and expectedVersion required. Strong administrative policy takes precedence.
// @Tags MFA
// @Accept json
// @Produce json
// @Param body body PreferenceRequest true "version and method"
// @Success 200 {object} PreferenceResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/preference [post]
func (h *PreferenceHandler) Update(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	var input PreferenceRequest
	if httpx.DecodeJSON(w, r, &input) != nil || input.Method == nil || input.ExpectedVersion == nil {
		httpx.Error(w, 400, "invalid_json", "method and expectedVersion required")
		return
	}
	result, err := h.service.Update(r.Context(), service.PreferenceUpdate{Proof: proof, Method: *input.Method, ExpectedVersion: *input.ExpectedVersion})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, PreferenceResponse{Version: result.Version, Method: result.Method})
}
