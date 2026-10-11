package router

import (
	"context"
	"net/http"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.uber.org/zap"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type Handlers struct {
	Session           *sessionhttp.Handler
	Rotation          *sessionhttp.RotationHandler
	Reauthentication  *passwordhttp.ReauthenticationHandler
	Recovery          *passwordhttp.RecoveryHandler
	Account           *accounthttp.Handler
	EmailChange       *accounthttp.EmailChangeHandler
	ProtectedRecovery *passwordhttp.ProtectedRecoveryHandler
	Activation        *passwordhttp.ActivationHandler
	TemporaryPassword *passwordhttp.TemporaryPasswordHandler
	PasswordHandler   *passwordhttp.PasswordHandler
	Middleware        *sessionhttp.Middleware
	MailTest          *dev.MailTestHandler
	Config            *config.Config
	Logger            *zap.Logger
	ReadyCheck        func(context.Context) error
}

func New(h Handlers) *chi.Mux {
	r := chi.NewRouter()

	log := h.Logger
	if log == nil {
		log = zap.NewNop()
	}
	r.Use(requestmiddleware.RequestLogger(log))
	r.Use(middleware.Recoverer)
	capacity := requestmiddleware.CapacityConfig{MaxInFlight: 128, RequestTimeout: 10 * time.Second}
	var proxy requestmiddleware.ProxyConfig
	if h.Config != nil {
		if h.Config.HTTP.MaxInFlight != 0 {
			capacity = h.Config.HTTP
		}
		proxy = h.Config.Proxy
	}
	r.Use(requestmiddleware.Admission(capacity))
	r.Use(requestmiddleware.ClientIP(proxy))
	r.Get("/health/live", live)
	r.Get("/health/ready", readiness(h.ReadyCheck))

	r.Get("/ping", ping)

	if h.Config != nil && h.Config.Swagger.Enabled {
		swagger := r.With(middleware.BasicAuth("swagger", map[string]string{h.Config.Swagger.Username: h.Config.Swagger.Password}))
		swagger.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
		})
		swagger.Get("/swagger/*", httpSwagger.WrapHandler)
	}

	r.Route("/api/v1/", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			if h.Session != nil {
				sessionRoutes(r, h)
			}
			if h.Recovery != nil {
				r.Post("/forgot-password", h.Recovery.Forgot)
				r.Post("/reset-password", h.Recovery.Reset)
			}
			if h.Activation != nil {
				var origins requestmiddleware.OriginConfig
				if h.Config != nil {
					origins = h.Config.Browser
				}
				r.With(noStore, requestmiddleware.RequireOrigin(origins)).Post("/invitations/activate", h.Activation.Activate)
			}
			if h.Account != nil {
				r.Post("/email/resend", h.Account.Resend)
				r.Post("/email/verify", h.Account.Confirm)
			}
			if h.TemporaryPassword != nil {
				var origins requestmiddleware.OriginConfig
				if h.Config != nil {
					origins = h.Config.Browser
				}
				setup := r.With(noStore, requestmiddleware.RequireOrigin(origins))
				setup.Post("/temporary-password/login", h.TemporaryPassword.Login)
				setup.Post("/temporary-password/complete", h.TemporaryPassword.Complete)
			}
			if h.EmailChange != nil {
				emailChangeRoutes(r, h)
			}
			r.Route("/register", func(r chi.Router) {
				if h.Account != nil {
					r.Use(h.Account.LimitRegistration)
				}
				r.Post("/email", h.PasswordHandler.Register)
			})

			r.Route("/login", func(r chi.Router) {
				r.Post("/email", h.PasswordHandler.LoginByEmail)
			})

			r.Group(func(r chi.Router) {
				r.Use(h.Middleware.Auth)
				if h.Account != nil {
					r.Use(h.Account.RequireVerified)
				}
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

func sessionRoutes(r chi.Router, h Handlers) {
	var cfg requestmiddleware.OriginConfig
	if h.Config != nil {
		cfg = h.Config.Browser
	}
	origin := requestmiddleware.RequireOrigin(cfg)
	if h.Reauthentication != nil {
		r.With(noStore, origin, h.Middleware.NoRefreshAuth).Post("/reauthenticate/password", h.Reauthentication.Confirm)
	}
	if h.Rotation != nil {
		r.With(noStore, origin, h.Middleware.NoRefreshAuth).Post("/session/rotate", h.Rotation.Rotate)
	}
	reads := r.With(noStore, h.Middleware.Auth)
	reads.Get("/me", h.Session.Me)
	reads.Get("/sessions", h.Session.List)
	mutations := r.With(noStore, origin, h.Middleware.Auth)
	mutations.Post("/logout-all", h.Session.LogoutAll)
	mutations.Delete("/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.Session.Revoke(w, r, chi.URLParam(r, "id"))
	})
	r.With(noStore, origin, h.Middleware.LogoutAuth).Post("/logout", h.Session.Logout)
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func emailChangeRoutes(r chi.Router, h Handlers) {
	var cfg requestmiddleware.OriginConfig
	if h.Config != nil {
		cfg = h.Config.Browser
	}
	mutations := r.With(noStore, requestmiddleware.RequireOrigin(cfg))
	mutations.With(h.Middleware.Auth).Post("/email/change", h.EmailChange.Request)
	mutations.Post("/email/change/confirm", h.EmailChange.Confirm)
	mutations.Post("/email/change/report", h.EmailChange.Report)
	if h.ProtectedRecovery != nil {
		mutations.Post("/email/change/recover", h.ProtectedRecovery.Recover)
	}
}
