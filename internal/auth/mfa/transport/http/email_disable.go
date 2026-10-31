package mfahttp

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (h *EmailHandler) DisableEmailFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := emailActionProof(w, r)
	if !ok {
		return
	}
	if err := h.factors.Disable(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
