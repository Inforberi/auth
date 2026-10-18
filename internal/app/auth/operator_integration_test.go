package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func TestOperatorProfileSQLHTTPS(t *testing.T) {
	admin, deps, cfg := operatorFixture(t)
	ctx := t.Context()
	repo, err := operatorpostgres.New(deps.pool, operatordomain.RealmID(cfg.Platform.RealmID))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckRuntime(ctx, true); err != nil {
		t.Fatal("restricted runtime rejected", err)
	}
	if err := repo.CheckRuntime(ctx, false); err == nil {
		t.Fatal("uninitialized runtime started without setup")
	}
	wrong, err := operatorpostgres.New(deps.pool, "1c82c477-3a57-4823-8c49-a476550d8a21")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.CheckRuntime(ctx, true); err == nil {
		t.Fatal("foreign platform marker accepted")
	}
	if _, err := admin.Exec(ctx, `REVOKE INSERT ON platform.operator_audit FROM auth_platform_operator_test`); err != nil {
		t.Fatal(err)
	}
	missingGrant := repo.CheckRuntime(ctx, true)
	if _, err := admin.Exec(ctx, `GRANT INSERT ON platform.operator_audit TO auth_platform_operator_test`); err != nil {
		t.Fatal(err)
	}
	if missingGrant == nil {
		t.Fatal("partial runtime privileges accepted")
	}
	for _, privilege := range []string{"UPDATE ON platform.operator_audit", "UPDATE(id) ON platform.operator_realm", "CREATE ON SCHEMA auth"} {
		if _, err := admin.Exec(ctx, "GRANT "+privilege+" TO "+operatorFixtureRole); err != nil {
			t.Fatal(err)
		}
		unsafeRole := repo.CheckRuntime(ctx, true)
		if _, err := admin.Exec(ctx, "REVOKE "+privilege+" FROM "+operatorFixtureRole); err != nil {
			t.Fatal(err)
		}
		if unsafeRole == nil {
			t.Fatal("excess runtime privileges accepted")
		}
	}
	mail := &operatorMailbox{messages: make(chan string, 8)}
	assembled, err := assembleOperator(ctx, cfg, deps, mail)
	if err != nil {
		t.Fatal("operator assembly", err)
	}
	t.Cleanup(assembled.resources.close)
	h := newOperatorHTTPS(t, assembled.handler, cfg.Platform.Origin)
	// Setup proof is an installation header, never a query string or login credential.
	startInput := map[string]string{"email": "operator@example.test", "password": "Initialpassword1"}
	startRequest, err := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/api/v1/setup/start", strings.NewReader(`{"email":"operator@example.test","password":"Initialpassword1"}`))
	if err != nil {
		t.Fatal(err)
	}
	startRequest.Host = "console.auth.example"
	startRequest.Header.Set("Origin", cfg.Platform.Origin)
	startRequest.Header.Set("Content-Type", "application/json")
	startRequest.Header.Set("X-Setup-Token", cfg.InitialSetup.Secret)
	response, err := h.client.Do(startRequest)
	if err != nil {
		t.Fatal(err)
	}
	var started map[string]json.RawMessage
	decodeErr := json.NewDecoder(response.Body).Decode(&started)
	_ = response.Body.Close()
	if response.StatusCode != 202 || decodeErr != nil {
		t.Fatal("operator setup start failed", response.StatusCode, decodeErr)
	}
	body := mail.receive(t)
	_, after, _ := strings.Cut(body, "<strong>")
	emailCode, _, _ := strings.Cut(after, "</strong>")
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(operatorField(t, started, "secret"), now)
	if err != nil {
		t.Fatal(err)
	}
	completeInput := map[string]string{"token": operatorField(t, started, "token"), "emailCode": emailCode, "totp": code}
	encoded, err := json.Marshal(completeInput)
	if err != nil {
		t.Fatal(err)
	}
	completeRequest, err := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/api/v1/setup/complete", strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	completeRequest.Host = startRequest.Host
	completeRequest.Header = startRequest.Header.Clone()
	response, err = h.client.Do(completeRequest)
	if err != nil {
		t.Fatal(err)
	}
	var completed struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	decodeErr = json.NewDecoder(response.Body).Decode(&completed)
	_ = response.Body.Close()
	if response.StatusCode != 200 || decodeErr != nil || len(completed.RecoveryCodes) != 10 {
		t.Fatal("operator setup complete failed", response.StatusCode, decodeErr)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionhttp.SessionCookieName && cookie.Value != "" {
			t.Fatal("setup issued a session")
		}
	}
	login, loginCookies := h.call("POST", "/api/v1/admin/auth/login/email", startInput, nil, 202)
	binding := operatorCookie(t, loginCookies, "__Host-mfa-login")
	_, cookies := h.call("POST", "/api/v1/auth/mfa/login/complete", map[string]any{"challenge": operatorField(t, login, "challenge"), "code": completed.RecoveryCodes[0], "recovery": true}, []*http.Cookie{binding}, 200)
	session := operatorCookie(t, cookies, sessionhttp.SessionCookieName)
	me, _ := h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 200)
	user := accountdomain.UserID(operatorField(t, me, "userId"))
	actor := operatordomain.Principal{UserID: user, TokenHash: tokengenerate.New().Hash(session.Value)}
	if err := repo.AuthorizeRead(ctx, actor, operatordomain.ProjectsRead); err != nil {
		t.Fatal("issued operator session lacks current authority", err)
	}
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)}}, 401)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- assembled.run(workerCtx, deps.log, func(ctx context.Context) error { <-ctx.Done(); return nil })
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	h.call("POST", "/api/v1/auth/forgot-password", map[string]string{"email": startInput["email"]}, nil, 202)
	resetBody := mail.receive(t)
	match := regexp.MustCompile(`[?&]token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(resetBody)
	if len(match) != 2 {
		t.Fatal("reset delivery missing bounded token")
	}
	h.call("POST", "/api/v1/auth/reset-password", map[string]string{"token": match[1], "newPassword": "Newpassword2", "confirmPassword": "Newpassword2"}, nil, 200)
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 401)
	if err := repo.AuthorizeRead(ctx, actor, operatordomain.ProjectsRead); !errors.Is(err, operatordomain.ErrForbidden) {
		t.Fatal("reset did not revoke platform authority", err)
	}
	login, loginCookies = h.call("POST", "/api/v1/admin/auth/login/email", map[string]string{"email": startInput["email"], "password": "Newpassword2"}, nil, 202)
	binding = operatorCookie(t, loginCookies, "__Host-mfa-login")
	_, cookies = h.call("POST", "/api/v1/auth/mfa/login/complete", map[string]any{"challenge": operatorField(t, login, "challenge"), "code": completed.RecoveryCodes[1], "recovery": true}, []*http.Cookie{binding}, 200)
	session = operatorCookie(t, cookies, sessionhttp.SessionCookieName)
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 200)
	h.call("POST", "/api/v1/auth/logout", map[string]string{}, []*http.Cookie{session}, 204)
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 401)
	cfg.InitialSetup.Enabled = false
	if _, err := assembleOperator(ctx, cfg, deps, mail); err != nil {
		t.Fatal("initialized realm cannot restart without setup secret", err)
	}
}
