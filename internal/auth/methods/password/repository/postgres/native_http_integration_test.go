package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func nativeHTTPFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context) (nativeEmailFixture, http.Handler, *passwordservice.PasswordService) {
	t.Helper()
	f := newNativeEmailFixture(t, db, ctx)
	password := passwordservice.New(New(db), nil, hasher.NewBounded(hasher.NewArgon2idHash(2, 16, 1024, 1, 32), 2), loginTestLimit{})
	primary, err := tokenservice.NewNativePasswordLogin(f.primary, password)
	if err != nil {
		t.Fatal(err)
	}
	h := tokenhttp.NewNative(tokenhttp.NativeServices{Password: primary, Email: f.login, MFA: f.primary, Enrollment: f.mfa, Tokens: f.tokens}, zap.NewNop())
	handler := router.New(router.Handlers{NativeTokens: h, Logger: zap.NewNop(), Config: &config.Config{JWT: tokensettings.Config{Enabled: true, NativeEnabled: true}, EmailOTP: otpservice.Config{Enabled: true}}})
	return f, handler, password
}

func nativeHTTPPost(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/auth"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:50000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "native-sql-test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func nativeHTTPDecode(t *testing.T, w *httptest.ResponseRecorder, status int, output any) {
	t.Helper()
	if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
		t.Fatal("native HTTP response", w.Code, w.Body.String(), w.Header())
	}
	if output != nil && json.Unmarshal(w.Body.Bytes(), output) != nil {
		t.Fatal("malformed native response")
	}
}

func nativePasswordBody(email string) string {
	return `{"email":"` + email + `","password":"Password12345","audience":"orders","scope":["orders.read"]}`
}
func nativeRefreshBody(raw string) string { return `{"refreshToken":"` + raw + `"}` }

func checkNativeHTTP(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("password login refresh replay logout and profile labels", func(t *testing.T) {
		f, handler, password := nativeHTTPFixture(t, db, ctx)
		var result tokenhttp.NativeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/password/login", nativePasswordBody(f.email)), 200, &result)
		if result.AccessToken == "" || result.RefreshToken == "" || result.TokenType != "Bearer" || result.Scope != "orders.read" {
			t.Fatal("missing native credentials")
		}
		proof, err := password.Authenticate(ctx, passwordservice.LoginInput{Email: f.email, Password: "Password12345", IP: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		browser := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(db), tokengenerate.New(), nativePolicyFixture().Sessions)
		created, err := browser.BeginLogin(ctx, proof, "browser fixture", "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		page, err := sessionservice.NewManagement(sessionpostgres.New(db)).List(ctx, f.user, tokengenerate.New().Hash(created.RawToken), "")
		if err != nil || len(page.Sessions) != 2 {
			t.Fatal("mixed profile list", err)
		}
		profiles := map[string]int{}
		for _, item := range page.Sessions {
			profiles[item.CredentialProfile]++
		}
		if profiles["browser"] != 1 || profiles["api"] != 1 {
			t.Fatal(profiles)
		}
		var rotated tokenhttp.NativeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(result.RefreshToken)), 200, &rotated)
		early := nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(rotated.RefreshToken))
		nativeHTTPDecode(t, early, 429, nil)
		if early.Header().Get("Retry-After") != "30" {
			t.Fatal("missing rotation delay")
		}
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(result.RefreshToken)), 401, nil)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(rotated.RefreshToken)), 401, nil)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/password/login", nativePasswordBody(f.email)), 200, &result)
		for range 2 {
			nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/logout", nativeRefreshBody(result.RefreshToken)), 204, nil)
		}
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(result.RefreshToken)), 401, nil)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/logout", nativeRefreshBody(created.RawToken)), 204, nil)
		if _, err := sessionpostgres.New(db).FindSession(ctx, tokengenerate.New().Hash(created.RawToken)); err != nil {
			t.Fatal("native logout revoked browser", err)
		}
	})
	t.Run("parallel HTTP refresh commits replay revocation", func(t *testing.T) {
		f, handler, _ := nativeHTTPFixture(t, db, ctx)
		var issued tokenhttp.NativeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/password/login", nativePasswordBody(f.email)), 200, &issued)
		var wg sync.WaitGroup
		responses := make(chan *httptest.ResponseRecorder, 2)
		for range 2 {
			wg.Go(func() { responses <- nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(issued.RefreshToken)) })
		}
		wg.Wait()
		close(responses)
		counts := map[int]int{}
		var successor tokenhttp.NativeResponse
		for w := range responses {
			counts[w.Code]++
			if w.Code == 200 {
				nativeHTTPDecode(t, w, 200, &successor)
			} else {
				nativeHTTPDecode(t, w, 401, nil)
			}
		}
		if counts[200] != 1 || counts[401] != 1 {
			t.Fatal("independent refresh winners", counts)
		}
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/token/refresh", nativeRefreshBody(successor.RefreshToken)), 401, nil)
	})
	t.Run("required enrollment requires fresh primary then recovery factor", func(t *testing.T) {
		f, handler, _ := nativeHTTPFixture(t, db, ctx)
		accessExec(t, db, ctx, `UPDATE auth.roles SET mfa_required=true WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, f.user)
		var challenge tokenhttp.NativeChallengeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/password/login", nativePasswordBody(f.email)), 202, &challenge)
		if challenge.NextStep != "enrollment" {
			t.Fatal("enrollment not required")
		}
		bound := `{"challenge":"` + challenge.Challenge + `","binding":"` + challenge.Binding + `"`
		var enrollment tokenhttp.NativeEnrollmentResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/mfa/enrollment", bound+`}`), 200, &enrollment)
		var codes tokenhttp.NativeRecoveryCodesResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/mfa/enrollment/confirm", bound+`,"token":"`+enrollment.Token+`","code":"`+mfaCode(t, db, ctx, enrollment.Secret, 0)+`"}`), 200, &codes)
		if len(codes.Codes) != 10 {
			t.Fatal("recovery codes absent")
		}
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/mfa/complete", bound+`,"code":"`+codes.Codes[0]+`","recovery":true}`), 400, nil)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/password/login", nativePasswordBody(f.email)), 202, &challenge)
		if challenge.NextStep != "mfa" {
			t.Fatal("factor was not required after enrollment")
		}
		complete := `{"challenge":"` + challenge.Challenge + `","binding":"` + challenge.Binding + `","code":"` + codes.Codes[0] + `","recovery":true}`
		var result tokenhttp.NativeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/mfa/complete", complete), 200, &result)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/mfa/complete", complete), 400, nil)
	})
	t.Run("email native request and one-use confirmation", func(t *testing.T) {
		f, handler, _ := nativeHTTPFixture(t, db, ctx)
		var requested tokenhttp.NativeEmailResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/email/request", `{"email":"`+f.email+`","audience":"orders","scope":["orders.read"]}`), 202, &requested)
		var encrypted []byte
		if err := db.QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, f.cipher.Digest("native:binding:"+requested.Binding)).Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		plain, err := f.cipher.Open(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		var mail struct {
			Body string `json:"body"`
		}
		if json.Unmarshal(plain, &mail) != nil {
			t.Fatal("synthetic outbox parse")
		}
		start := strings.Index(mail.Body, "<strong>") + len("<strong>")
		body := `{"binding":"` + requested.Binding + `","code":"` + mail.Body[start:start+8] + `"}`
		var result tokenhttp.NativeResponse
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/email/confirm", body), 200, &result)
		nativeHTTPDecode(t, nativeHTTPPost(handler, "/native/email/confirm", body), 400, nil)
	})
}
