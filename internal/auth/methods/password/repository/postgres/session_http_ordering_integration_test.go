package postgres

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkSessionHTTPResponseOrdering(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, operation := range []string{"rotate", "reauthenticate", "logout", "logout-all"} {
		t.Run(operation, func(t *testing.T) {
			f := newStatusFixture(t, db, ctx, "http-order-"+operation)
			tokens := tokengenerate.New()
			raw, err := tokens.GenerateToken()
			if err != nil {
				t.Fatal(err)
			}
			oldHash := tokens.Hash(raw)
			accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE token_hash=$1`, f.params.TokenHash, oldHash)
			before, err := f.sessions.FindSession(ctx, oldHash)
			if err != nil {
				t.Fatal(err)
			}
			cfg := sessionservice.Config{SessionTTL: 90 * time.Minute, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: 75 * time.Minute}
			sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokens, cfg)
			middleware := sessionhttp.New(sessions, zap.NewNop())
			management := sessionhttp.NewHandler(sessionservice.NewManagement(f.sessions), zap.NewNop())
			rotation := sessionhttp.NewRotation(sessionservice.NewRotation(f.sessions, tokens), zap.NewNop())
			middle := httptest.NewRecorder()
			request := func(method string) *http.Request {
				r := httptest.NewRequest(method, "/", nil).WithContext(ctx)
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: raw})
				return r
			}
			late := httptest.NewRecorder()
			// A has already validated/refreshed; B commits before A sends its response.
			middleware.Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				action := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch operation {
					case "rotate":
						rotation.Rotate(w, r)
					case "logout":
						management.Logout(w, r)
					case "logout-all":
						management.LogoutAll(w, r)
					case "reauthenticate":
						replacement, err := tokens.GenerateToken()
						if err != nil {
							t.Fatal(err)
						}
						proof, err := f.sessions.ConfirmPassword(ctx, f.user, oldHash, "old-hash", 1, tokens.Hash(replacement))
						if err != nil {
							t.Fatal(err)
						}
						sessionhttp.SetSessionCookie(w, replacement, proof.ExpiresAt)
						w.WriteHeader(204)
					}
				})
				middleware.NoRefreshAuth(action).ServeHTTP(middle, request("POST"))
				if middle.Code != 204 {
					t.Fatal("lifecycle failed", middle.Code, middle.Body.String())
				}
				// A's stale principal must not authorize a write after B's commit.
				if err := f.sessions.RevokeOwnSession(ctx, f.user, oldHash, before.ID); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
					t.Fatal("stale principal authorized mutation", err)
				}
				w.WriteHeader(200)
			})).ServeHTTP(late, request("GET"))
			oldCookies, newCookies := late.Result().Cookies(), middle.Result().Cookies()
			if late.Code != 200 || len(oldCookies) != 1 || oldCookies[0].Value != raw || len(newCookies) != 1 {
				t.Fatal("response ordering not exercised", late.Code, oldCookies, newCookies)
			}
			if _, err := sessions.ValidateSessionWithoutRefresh(ctx, oldCookies[0].Value); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
				t.Fatal("late cookie resurrected access", err)
			}
			if operation == "rotate" || operation == "reauthenticate" {
				if newCookies[0].Value == raw {
					t.Fatal("verifier not replaced")
				}
				if _, err := sessions.ValidateSessionWithoutRefresh(ctx, newCookies[0].Value); err != nil {
					t.Fatal("winning token lost", err)
				}
			} else if newCookies[0].MaxAge != -1 {
				t.Fatal("logout did not clear cookie")
			}
			w := httptest.NewRecorder()
			middleware.NoRefreshAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("old cookie authorized read") })).ServeHTTP(w, request("GET"))
			if w.Code != 401 || len(w.Result().Cookies()) != 0 {
				t.Fatal("stale read changed cookie", w.Code)
			}
		})
	}
}
