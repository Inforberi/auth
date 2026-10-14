package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func checkMFARecoveryHTTP(t *testing.T, owner, runtime *pgxpool.Pool, ctx context.Context, op *mfapostgres.Repository) {
	t.Run("HTTP-operator-completion-and-disabled-delivery", func(t *testing.T) {
		f := prepareLostFactor(t, owner, ctx, "http", true)
		repo := mfapostgres.New(runtime)
		if err := repo.CheckRecoveryOperator(ctx); err != nil {
			t.Fatal("runtime startup", err)
		}
		service := recoveryService(t, runtime, nil)
		cfg := &config.Config{MFA: mfaservice.Config{Enabled: true, RecoveryEnabled: true}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}}
		sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour})
		h := router.Handlers{MFA: mfahttp.NewWithRecovery(mfaService(t, runtime), f.login, service, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()), Config: cfg}
		send := func(action, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "https://localhost:8443/api/v1/auth/mfa/recovery/"+action, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://localhost:8443")
			r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: f.input.Binding})
			w := httptest.NewRecorder()
			router.New(h).ServeHTTP(w, r)
			return w
		}
		start := send("start", `{"challenge":"`+f.input.Token+`"}`)
		var candidate mfahttp.RecoveryCandidateResponse
		if err := json.Unmarshal(start.Body.Bytes(), &candidate); err != nil || start.Code != 200 || candidate.RequestID == f.candidate.RequestID || candidate.Secret == "" || start.Header().Get("Cache-Control") != "no-store" || len(start.Result().Cookies()) != 0 {
			t.Fatal("HTTP start", start.Code, start.Body.String(), err)
		}
		body := `{"requestId":"` + candidate.RequestID + `","challenge":"` + f.input.Token + `","code":"` + mfaCode(t, owner, ctx, candidate.Secret, 0) + `"}`
		if denied := send("complete", body); denied.Code != 400 || len(denied.Result().Cookies()) != 0 {
			t.Fatal("unapproved HTTP complete", denied.Code)
		}
		f.decision.RequestID = candidate.RequestID
		if err := op.DecideRecovery(ctx, f.decision); err != nil {
			t.Fatal(err)
		}
		complete := send("complete", body)
		var codes mfahttp.RecoveryCodesResponse
		if err := json.Unmarshal(complete.Body.Bytes(), &codes); err != nil || complete.Code != 200 || len(codes.Codes) != 10 {
			t.Fatal("HTTP completion", complete.Code, complete.Body.String(), err)
		}
		for _, cookie := range complete.Result().Cookies() {
			if cookie.MaxAge != -1 || !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("issued recovery session", cookie)
			}
		}
		var active int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.user).Scan(&active); err != nil || active != 0 {
			t.Fatal("session created", active, err)
		}
		if replay := send("complete", body); replay.Code != 400 {
			t.Fatal("HTTP replay", replay.Code)
		}
		cfg.MFA.RecoveryEnabled = false
		if disabled := send("start", `{"challenge":"`+f.input.Token+`"}`); disabled.Code != 404 {
			t.Fatal("disabled route", disabled.Code)
		}
		mail := &recoveryMailer{}
		worker, err := mfaservice.NewRecoveryDelivery(repo, recoveryCipher(t), mail)
		if err != nil {
			t.Fatal(err)
		}
		if processed, err := worker.DeliverOne(ctx); !processed || err != nil || mail.to != f.email {
			t.Fatal("disabled recovery lost committed notice", err)
		}
	})
}
