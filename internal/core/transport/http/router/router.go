package router

import (
	"net/http"

	login_http "github.com/Inforberi/financial-intelligence/internal/featers/login/transport/http"
	register_http "github.com/Inforberi/financial-intelligence/internal/featers/register/transport/http"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Handlers struct {
	Register *register_http.RegisterHandler
	Login    *login_http.LoginHandler
}

func New(h Handlers) *chi.Mux {
	r := chi.NewRouter()

	// middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// health check
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	// swagger
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
	})
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	// routes
	r.Route("/api/v1/", func(r chi.Router) {
		// auth
		r.Route("/auth", func(r chi.Router) {
			//register
			r.Route("/register", func(r chi.Router) {
				r.Post("/email", h.Register.RegisterByEmail)
			})

			// login
			r.Route("/login", func(r chi.Router) {
				r.Post("/email", h.Login.Login)
			})
		})
	})

	return r
}
