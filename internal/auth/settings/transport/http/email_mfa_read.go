package http

import (
	"net/http"
)

func (h *EmailMFAHandler) Read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.Read(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
