package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type catalogService interface {
	Rename(context.Context, operatordomain.Principal, domain.Rename) (domain.NameReceipt, error)
	List(context.Context, operatordomain.Principal, service.ListInput) (service.ListResult, error)
	Read(context.Context, operatordomain.Principal, domain.ID) (domain.Project, error)
	ChangeState(context.Context, operatordomain.Principal, domain.Action, service.ChangeStateInput) (domain.TransitionReceipt, error)
	Create(context.Context, operatordomain.Principal, service.CreateInput) (domain.CreationReceipt, error)
}

type Handler struct {
	preparation     PreparationOperations
	deletionPreview DeletionPreview
	deletion        DeletionOperations
	service         catalogService
	log             *zap.Logger
}

func New(service catalogService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

type ProjectResponse struct {
	ID           domain.ID           `json:"id" swaggertype:"string"`
	Slug         string              `json:"slug"`
	Name         string              `json:"name"`
	Origin       string              `json:"origin"`
	DesiredState domain.DesiredState `json:"desiredState" swaggertype:"string"`
	Phase        domain.Phase        `json:"phase" swaggertype:"string"`
	Version      int64               `json:"version"`
	Generation   int64               `json:"generation"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
} // @name project_http.ProjectResponse

func projectResponse(p domain.Project) ProjectResponse {
	return ProjectResponse{
		ID: p.ID, Slug: p.Slug, Name: p.Name, Origin: p.Origin, DesiredState: p.DesiredState,
		Phase: p.Phase, Version: p.Version, Generation: p.Generation, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func RequestActor(w http.ResponseWriter, r *http.Request) (operatordomain.Principal, bool) {
	w.Header().Set("Cache-Control", "no-store")
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return operatordomain.Principal{}, false
	}
	return operatordomain.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}

var catalogErrors = []httpx.ErrorRule{
	httpx.MatchError(operatordomain.ErrForbidden, 403, "forbidden", "forbidden"),
	httpx.MatchError(operatordomain.ErrFreshAuthRequired, 428, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(domain.ErrInvalidPage, 400, "invalid_query", "invalid project query"),
	httpx.MatchError(domain.ErrInvalidProject, 400, "invalid_project", "invalid project"),
	httpx.MatchError(domain.ErrNotFound, 404, "project_not_found", "project not found"),
	httpx.MatchError(domain.ErrConflict, 409, "project_conflict", "project version or operation conflict"),
	httpx.MatchError(domain.ErrInvalidTransition, 409, "invalid_transition", "invalid project transition"),
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_catalog", err, catalogErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

func CatalogErrorRules() []httpx.ErrorRule { return append([]httpx.ErrorRule(nil), catalogErrors...) }
