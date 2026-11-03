package mfamanagementhttp

import (
	"net/http"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read the user's preferred MFA method
// @Tags MFA
// @Produce json
// @Success 200 {object} PreferenceResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/preference [get]
func (h *PreferenceHandler) Read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.RequestProof(w, r)
	if !ok {
		return
	}
	result, err := h.service.Read(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, PreferenceResponse{Version: result.Version, Method: result.Method})
}
