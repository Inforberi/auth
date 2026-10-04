package router

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/dev"
	core_middleware "github.com/Inforberi/financial-intelligence/internal/core/transport/http/middleware"
	password_http "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/transport/http"
)

type Handlers struct {
	PasswordHandler *password_http.PasswordHandler
	Middleware      *core_middleware.Middleware
	MailTest        *dev.MailTestHandler
	Config          *config.Config
	Logger          *zap.Logger
	ReadyCheck      func(context.Context) error
}

func New(h Handlers) *chi.Mux {
	r := chi.NewRouter()

	log := h.Logger
	if log == nil {
		log = zap.NewNop()
	}
	r.Use(core_middleware.RequestLogger(log))
	r.Use(middleware.Recoverer)
	r.Get("/health/live", live)
	r.Get("/health/ready", readiness(h.ReadyCheck))

	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("pong")); err != nil {
			return
		}
	})

	if h.Config != nil && h.Config.Swagger.Enabled {
		swagger := r.With(middleware.BasicAuth("swagger", map[string]string{h.Config.Swagger.Username: h.Config.Swagger.Password}))
		swagger.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
		})
		swagger.Get("/swagger/*", httpSwagger.WrapHandler)
	}

	r.Route("/api/v1/", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Route("/register", func(r chi.Router) {
				r.Post("/email", h.PasswordHandler.Register)
			})

			r.Route("/login", func(r chi.Router) {
				r.Post("/email", h.PasswordHandler.LoginByEmail)
			})

			r.Group(func(r chi.Router) {
				r.Use(h.Middleware.Auth)
				r.Post("/change-password", h.PasswordHandler.ChangePassword)
			})
		})

		if h.MailTest != nil && h.Config != nil && h.Config.Logger.Env == "dev" {
			r.Route("/dev", func(r chi.Router) {
				r.Post("/send-mail", h.MailTest.Send)
			})
		}
	})

	return r
}
