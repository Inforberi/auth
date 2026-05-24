package register_http

import (
	"log"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/httpx"
)

type RegisterByEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterByEmailResponse struct {
	UserID domain.UserID `json:"userID"`
}

func (h *registerHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	// decode json
	var input RegisterByEmailRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeInvalidJSON,
			"Invalid JSON",
		)
		return

	}

	// validate request
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

	// call service
	register, err := h.service.RegisterByEmail(
		r.Context(),
		input.Email,
		input.Password,
		userAgent,
		ip,
	)
	if err != nil {
		log.Printf("register error: %+v\n", err)
		errs := mapError(err)
		httpx.Error(
			w,
			errs.Status,
			errs.Code,
			errs.Message,
		)
		return
	}

	httpx.SetSessionCookie(
		w,
		register.Token,
		register.ExpiresAt,
	)

	// write response
	httpx.JSON(
		w,
		http.StatusCreated,
		RegisterByEmailResponse{
			UserID: register.UserID,
		},
	)

}
