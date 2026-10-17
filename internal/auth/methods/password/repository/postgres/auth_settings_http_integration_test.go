package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func checkSettingsRuntimeHTTP(t *testing.T, db *pgxpool.Pool, ctx context.Context, actor accessservice.Principal, before settingsdomain.Snapshot) {
	t.Helper()
	input := settingsservice.UpdateInput{Actor: actor, ExpectedVersion: before.Version, Policy: before.Policy}
	if _, err := settingsservice.New(settingspostgres.New(db)).Update(ctx, input); !errors.Is(err, settingsdomain.ErrMethodNotReady) {
		t.Fatal("unbound repository accepted mutation", err)
	}
	available := settingsdomain.PublicMethods{Password: true}
	svc := settingsservice.New(settingspostgres.NewWithRuntime(db, available, settingsdomain.TokenIssuance{}))
	h := settingshttp.New(svc, available, zap.NewNop())
	request := httptest.NewRequest("GET", "/api/v1/admin/auth/settings", nil)
	request = request.WithContext(sessionhttp.SetAuthContext(ctx, sessionhttp.Auth{UserID: actor.UserID, TokenHash: actor.TokenHash}))
	w := httptest.NewRecorder()
	h.Read(w, request)
	var read settingshttp.SettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil || w.Code != 200 || read.Version != before.Version || read.AvailableMethods.Google {
		t.Fatal("SQL-backed read", w.Code, read, err)
	}
	for _, enableGoogle := range []bool{false, true} {
		policy := read.Policy
		policy.Methods.Google = enableGoogle
		body, err := json.Marshal(map[string]any{"expectedVersion": read.Version, "policy": policy})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/api/v1/admin/auth/settings", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(sessionhttp.SetAuthContext(ctx, sessionhttp.Auth{UserID: actor.UserID, TokenHash: actor.TokenHash}))
		w := httptest.NewRecorder()
		h.Update(w, request)
		want := 200
		if enableGoogle {
			want = 409
		}
		if w.Code != want || len(w.Result().Cookies()) != 0 || (want == 200 && w.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("runtime/no-op contract", w.Code, w.Body.String(), before.Policy, policy)
		}
	}
	if got, err := svc.Read(ctx, actor); err != nil || got != before {
		t.Fatal("rejected update changed settings", got, err)
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings_audit`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("read/no-op/unavailable wrote audit", audits, err)
	}
}
