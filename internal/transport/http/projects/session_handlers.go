package browser

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func bindSessionHandlers(s *projectprofile.SessionRuntime, handlers map[string]http.HandlerFunc, log *zap.Logger) {
	h := sessionhttp.NewHandler(s, log)
	handlers["/api/v1/auth/me"], handlers["/api/v1/auth/sessions"] = h.Me, h.List
	handlers["/api/v1/auth/logout"], handlers["/api/v1/auth/logout-all"] = h.Logout, h.LogoutAll
	handlers["/api/v1/auth/sessions/{id}"] = func(w http.ResponseWriter, r *http.Request) {
		h.Revoke(w, r, chi.URLParam(r, "id"))
	}
	handlers["/api/v1/auth/session/activity"] = sessionhttp.NewActivity(s, log).Record
	handlers["/api/v1/auth/session/rotate"] = sessionhttp.NewRotation(s, log).Rotate
}
