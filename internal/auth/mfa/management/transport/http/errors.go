package mfamanagementhttp

import (
	"net/http"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondError(w, r, h.log, err)
}
