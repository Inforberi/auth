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
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
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
	Telegram          *telegramhttp.Handler
	EmailOTP          *otphttp.Handler
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
	r.Use(requestmiddleware.SecurityHeaders)
	r.Use(requestmiddleware.Recoverer(log))
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
			r.Use(browserProtection(h))
			emailOTPRoutes(r, h)
			if h.Telegram != nil && h.Config != nil && h.Config.Telegram.Enabled {
				r.Post("/telegram/start", h.Telegram.Start)
				r.Get("/telegram/callback", h.Telegram.Callback)
				r.With(h.Middleware.NoRefreshAuth).Post("/telegram/link", h.Telegram.StartLink)
				r.With(h.Middleware.NoRefreshAuth).Delete("/telegram/link", h.Telegram.Unlink)
			}
			if h.Session != nil {
				sessionRoutes(r, h)
			}
			if h.Recovery != nil {
				r.Post("/forgot-password", h.Recovery.Forgot)
				r.Post("/reset-password", h.Recovery.Reset)
			}
			if h.Activation != nil {
				r.Post("/invitations/activate", h.Activation.Activate)
			}
			if h.Account != nil {
				r.Post("/email/resend", h.Account.Resend)
				r.Post("/email/verify", h.Account.Confirm)
			}
			if h.TemporaryPassword != nil {
				r.Post("/temporary-password/login", h.TemporaryPassword.Login)
				r.Post("/temporary-password/complete", h.TemporaryPassword.Complete)
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
				r.Use(browserProtection(h))
				r.Post("/send-mail", h.MailTest.Send)
			})
		}
	})

	return r
}

func emailOTPRoutes(r chi.Router, h Handlers) {
	if h.EmailOTP != nil && h.Config != nil && h.Config.EmailOTP.Enabled {
		r.Post("/email-otp/request", h.EmailOTP.Request)
		r.Post("/email-otp/confirm", h.EmailOTP.Confirm)
	}
}

func sessionRoutes(r chi.Router, h Handlers) {
	if h.Reauthentication != nil {
		r.With(h.Middleware.NoRefreshAuth).Post("/reauthenticate/password", h.Reauthentication.Confirm)
	}
	if h.Rotation != nil {
		r.With(h.Middleware.NoRefreshAuth).Post("/session/rotate", h.Rotation.Rotate)
	}
	reads := r.With(h.Middleware.Auth)
	reads.Get("/me", h.Session.Me)
	reads.Get("/sessions", h.Session.List)
	mutations := r.With(h.Middleware.Auth)
	mutations.Post("/logout-all", h.Session.LogoutAll)
	mutations.Delete("/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.Session.Revoke(w, r, chi.URLParam(r, "id"))
	})
	r.With(h.Middleware.LogoutAuth).Post("/logout", h.Session.Logout)
}

func browserProtection(h Handlers) func(http.Handler) http.Handler {
	var cfg requestmiddleware.OriginConfig
	if h.Config != nil {
		cfg = h.Config.Browser
	}
	return requestmiddleware.BrowserProtection(cfg)
}

func emailChangeRoutes(r chi.Router, h Handlers) {
	r.With(h.Middleware.Auth).Post("/email/change", h.EmailChange.Request)
	r.Post("/email/change/confirm", h.EmailChange.Confirm)
	r.Post("/email/change/report", h.EmailChange.Report)
	if h.ProtectedRecovery != nil {
		r.Post("/email/change/recover", h.ProtectedRecovery.Recover)
	}
}
