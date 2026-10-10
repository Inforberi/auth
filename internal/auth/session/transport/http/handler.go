package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ManagementService interface {
	List(context.Context, accountdomain.UserID, string, string) (*service.SessionPage, error)
	Revoke(context.Context, accountdomain.UserID, string, string) error
	LogoutAll(context.Context, accountdomain.UserID, string) error
}

type Handler struct {
	service ManagementService
	log     *zap.Logger
}

func NewHandler(service ManagementService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, op string, err error) {
	httpx.RespondError(w, r, h.log, op, err, managementErrors, dependencyFailure)
}

func requireAuth(w http.ResponseWriter, r *http.Request) (Auth, bool) {
	w.Header().Set("Cache-Control", "no-store")
	auth, ok := GetAuthContext(r.Context())
	if !ok {
		unauthorized(w)
	}
	return auth, ok
}
