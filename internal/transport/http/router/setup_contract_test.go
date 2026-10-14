package router

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

type contractSetup struct {
	calls    int
	operator string
	err      error
}

func (f *contractSetup) Start(_ context.Context, in accountservice.SetupStartInput) (*accountservice.SetupStarted, error) {
	f.calls++
	f.operator = in.OperatorSecret
	return &accountservice.SetupStarted{Token: "intent", Secret: "secret", URI: "otpauth://test", ExpiresAt: time.Now()}, f.err
}

func (f *contractSetup) Complete(_ context.Context, in accountservice.SetupCompleteInput) (*accountservice.SetupCompleted, error) {
	f.calls++
	f.operator = in.OperatorSecret
	return &accountservice.SetupCompleted{RecoveryCodes: []string{"code"}}, f.err
}

func TestSetupRoutes(t *testing.T) {
	for _, action := range []string{"start", "complete"} {
		for _, mode := range []string{"ok", "disabled", "mfa-disabled", "origin", "get", "authority", "closed"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
				h := contractHandlers("prod")
				f := &contractSetup{}
				h.Setup = accounthttp.NewSetup(f, zap.NewNop())
				h.Config.InitialSetup.Enabled = true
				body := `{"email":"owner@example.test","password":"Validpass1"}`
				want := 202
				if action == "complete" {
					body = `{"token":"intent","emailCode":"12345678","totp":"123456"}`
					want = 200
				}
				method := "POST"
				switch mode {
				case "disabled":
					h.Config.InitialSetup.Enabled = false
					want = 404
				case "mfa-disabled":
					h.Config.MFA.Enabled = false
					want = 404
				case "origin":
					want = 403
				case "get":
					method = "GET"
					want = 405
				case "authority":
					body = `{"userId":"attacker","verified":true,"role":"super_admin"}`
					want = 400
				case "closed":
					f.err = accountdomain.ErrSetupClosed
					want = 404
				}
				r := httptest.NewRequest(method, "https://localhost:8443/api/v1/setup/"+action, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				r.Header.Set("X-Setup-Token", "operator")
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.test")
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != want || len(w.Result().Cookies()) != 0 {
					t.Fatal(w.Code, w.Body.String())
				}
				if mode == "ok" || mode == "closed" {
					if f.calls != 1 || f.operator != "operator" || w.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("wrong setup authority")
					}
				} else if f.calls != 0 {
					t.Fatal("called rejected flow")
				}
			})
		}
	}
}
