package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type userDirectoryService interface {
	List(context.Context, accessservice.Principal, service.UserListInput) (service.UserPage, error)
	Read(context.Context, accessservice.Principal, domain.UserID) (service.UserDetail, error)
}

type UserDirectoryHandler struct {
	service userDirectoryService
	log     *zap.Logger
}

func NewUserDirectory(service userDirectoryService, log *zap.Logger) *UserDirectoryHandler {
	return &UserDirectoryHandler{service: service, log: log}
}

type UserSummaryResponse struct {
	ID            domain.UserID `json:"id" swaggertype:"string"`
	Status        domain.Status `json:"status" swaggertype:"string"`
	CreatedAt     time.Time     `json:"createdAt"`
	DisplayName   *string       `json:"displayName"`
	Email         *string       `json:"email"`
	EmailVerified bool          `json:"emailVerified"`
} // @name account_http.UserSummaryResponse

func userSummaryResponse(user service.UserSummary) UserSummaryResponse {
	return UserSummaryResponse{ID: user.ID, Status: user.Status, CreatedAt: user.CreatedAt, DisplayName: user.DisplayName, Email: user.Email, EmailVerified: user.EmailVerified}
}

var userDirectoryErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidUserQuery, 400, "invalid_query", "invalid user query"),
	httpx.MatchError(domain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrAccountNotFound, 404, "user_not_found", "user not found"),
	httpx.MatchError(domain.ErrUserDirectoryConflict, 409, "directory_conflict", "user directory data exceeds supported bounds"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
}

func (h *UserDirectoryHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "user_directory", err, userDirectoryErrors, dependencyFailure)
}
