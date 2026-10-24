package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type userService interface {
	ListProjectUsers(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountservice.UserListInput) (accountservice.UserPage, error)
	ReadProjectUser(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID) (accountservice.UserDetail, error)
}

type UserHandler struct {
	service userService
	log     *zap.Logger
}

func NewUsers(service userService, log *zap.Logger) *UserHandler {
	return &UserHandler{service: service, log: log}
}

var projectUserErrors = append(accounthttp.UserDirectoryErrorRules(), catalogErrors...)

func (h *UserHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_users", err, projectUserErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
