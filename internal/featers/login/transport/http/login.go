package login_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
)

type LoginByEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginByEmailResponse struct {
	status string
}

// @Summary login by email
// @Description login by email/password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body LoginByEmailRequest true "login payload"
// @Success 200 {object} LoginByEmailResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 500 {object} httpx.ErrorResponse
// @Router /auth/login/email [post]

func (l *loginHandler) Login(w http.ResponseWriter, r *http.Request) {
	// get input data
	var input LoginByEmailRequest
	if err := httpx.DecodeJSON(w, r, input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeInvalidJSON,
			"Invalid JSON",
		)
	}

	// base validate
	if input.Email == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeEmailRequired,
			"Email required",
		)
		return
	}

	if input.Password == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodePasswordRequired,
			"Password required",
		)
		return
	}

	userAgent := httpx.UserAgent(r)
	ip := httpx.IP(r)

	// call service login
	login, err := l.service.Login(r.Context(), login_domain.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		UserAgent: userAgent,
		IP:        ip,
	})

	if err != nil {
		errs := mapError(err)
		httpx.Error(
			w,
			errs.Status,
			errs.Code,
			errs.Message,
		)
	}

	// set coockie
	httpx.SetSessionCookie(
		w,
		login.Token,
		login.ExpiresAt,
	)

	httpx.JSON(
		w,
		http.StatusOK,
		LoginByEmailResponse{
			status: "ok",
		},
	)

}
