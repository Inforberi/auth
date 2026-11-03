package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountsetuphttp "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/transport/http"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func onboardingProfile(setup *contractSetup) ProjectOnboardingHTTP {
	return ProjectOnboardingHTTP{
		Origin: "https://project.example.test:8443",
		Setup:  accountsetuphttp.NewSetup(setup, zap.NewNop()),
		Capacity: requestmiddleware.CapacityConfig{
			MaxInFlight: 2, RequestTimeout: time.Second,
		},
		Admit: func(context.Context) (bool, error) { return true, nil },
	}
}

func onboardingRequest(action string) *http.Request {
	body := `{"email":"owner@example.test","password":"Validpass1"}`
	if action == "complete" {
		body = `{"token":"intent","emailCode":"12345678","totp":"123456"}`
	}
	r := httptest.NewRequest("POST", "https://project.example.test:8443/api/v1/setup/"+action, strings.NewReader(body))
	r.Header.Set("Origin", "https://project.example.test:8443")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Setup-Token", "project-proof")
	return r
}

func TestProjectOnboardingProfileValidation(t *testing.T) {
	for _, mode := range []string{"origin", "plaintext", "path", "ip", "setup", "admission", "capacity", "timeout", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			profile := onboardingProfile(&contractSetup{})
			switch mode {
			case "origin":
				profile.Origin = ""
			case "plaintext":
				profile.Origin = "http://project.example.test"
			case "path":
				profile.Origin += "/setup"
			case "ip":
				profile.Origin = "https://127.0.0.1"
			case "setup":
				profile.Setup = nil
			case "admission":
				profile.Admit = nil
			case "capacity":
				profile.Capacity.MaxInFlight = 0
			case "timeout":
				profile.Capacity.RequestTimeout = 0
			case "proxy":
				profile.Proxy.TrustedCIDRs = []string{"not-a-cidr"}
			}
			if handler, err := NewProjectOnboarding(profile); err == nil || handler != nil {
				t.Fatal("accepted incomplete profile")
			}
		})
	}
}

func TestProjectOnboardingRequests(t *testing.T) {
	for _, action := range []string{"start", "complete"} {
		for _, mode := range []string{"ok", "host", "port", "tls", "forwarded-host", "origin", "no-origin", "duplicate-origin", "inactive", "dependency", "cancelled", "closed", "unauthorized"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
				setup := &contractSetup{}
				profile := onboardingProfile(setup)
				checks := 0
				profile.Admit = func(ctx context.Context) (bool, error) {
					checks++
					if _, ok := ctx.Deadline(); !ok {
						t.Error("admission without request deadline")
					}
					if mode == "dependency" {
						return true, errors.New("private catalog error")
					}
					return mode != "inactive", nil
				}
				r := onboardingRequest(action)
				want, wantChecks, wantCalls := 202, 1, 1
				if action == "complete" {
					want = 200
				}
				switch mode {
				case "host", "port", "tls", "forwarded-host":
					want, wantChecks, wantCalls = 404, 0, 0
					switch mode {
					case "tls":
						r.TLS = nil
						r.Header.Set("X-Forwarded-Proto", "https")
					case "port":
						r.Host = "project.example.test"
					default:
						r.Host = "other.example.test:8443"
						r.Header.Set("X-Forwarded-Host", "project.example.test:8443")
						r.Header.Set("Forwarded", `host="project.example.test:8443";proto=https`)
					}
				case "origin", "no-origin", "duplicate-origin":
					want, wantChecks, wantCalls = 403, 0, 0
					switch mode {
					case "origin":
						r.Header.Set("Origin", "https://platform.example.test")
					case "no-origin":
						r.Header.Del("Origin")
					default:
						r.Header.Add("Origin", profile.Origin)
					}
				case "inactive":
					want, wantCalls = 404, 0
				case "dependency", "cancelled":
					want, wantCalls = 503, 0
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(r.Context())
						cancel()
						r = r.WithContext(ctx)
					}
				case "closed":
					setup.err, want = accountdomain.ErrSetupClosed, 404
				case "unauthorized":
					setup.err, want = accountdomain.ErrSetupUnauthorized, 403
				}
				handler, err := NewProjectOnboarding(profile)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != want || checks != wantChecks || setup.calls != wantCalls {
					t.Fatalf("status=%d checks=%d calls=%d: %s", w.Code, checks, setup.calls, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(w.Body.String(), "private catalog") {
					t.Fatal("unsafe response", w.Header(), w.Body.String())
				}
				if wantCalls != 0 && setup.operator != "project-proof" {
					t.Fatal("lost setup authority")
				}
			})
		}
	}
}

func TestProjectOnboardingDoesNotPublishOrdinaryRoutes(t *testing.T) {
	setup := &contractSetup{}
	profile := onboardingProfile(setup)
	checks := 0
	profile.Admit = func(context.Context) (bool, error) { checks++; return true, nil }
	handler, err := NewProjectOnboarding(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/forgot-password",
		"/api/v1/auth/mfa/login/complete", "/api/v1/auth/settings", "/api/v1/roles",
		"/api/v1/platform/projects", "/.well-known/jwks.json", "/swagger/index.html",
		"/health/ready", "/health/live", "/ping", "/api/v1/setup/unknown",
	} {
		for _, method := range []string{"GET", "POST", "OPTIONS"} {
			r := onboardingRequest("start")
			r.Method, r.URL.Path = method, path
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Errorf("%s %s: %d", method, path, w.Code)
			}
		}
	}
	for _, method := range []string{"GET", "HEAD", "PUT", "DELETE", "OPTIONS"} {
		r := onboardingRequest("start")
		r.Method = method
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 405 {
			t.Errorf("setup %s: %d", method, w.Code)
		}
	}
	if checks != 0 || setup.calls != 0 {
		t.Fatal("unknown route reached catalog or setup")
	}
}

func TestProjectOnboardingRechecksAdmission(t *testing.T) {
	setup := &contractSetup{}
	profile := onboardingProfile(setup)
	active, checks := true, 0
	profile.Admit = func(context.Context) (bool, error) { checks++; return active, nil }
	handler, err := NewProjectOnboarding(profile)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{202, 404, 202} {
		active = i != 1
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, onboardingRequest("start"))
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if checks != 3 || setup.calls != 2 {
		t.Fatal("admission cached", checks, setup.calls)
	}
}
