package router

import (
	"net/http"

	core_middleware "github.com/Inforberi/financial-intelligence/internal/core/transport/http/middleware"
	password_http "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/transport/http"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Handlers struct {
	PasswordHandler *password_http.PasswordHandler
	Middleware      *core_middleware.Middleware
}

func New(h Handlers) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
	})
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1/", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Route("/register", func(r chi.Router) {
				r.Post("/email", h.PasswordHandler.Register)
			})

			r.Route("/login", func(r chi.Router) {
				r.Post("/email", h.PasswordHandler.LoginByEmail)
			})
		})
	})

	return r
}
