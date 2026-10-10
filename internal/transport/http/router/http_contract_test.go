package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestHTTPResponsesMatchSwagger(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		path, body, token, code string
		status                  int
		cookie                  bool
	}{
		{"/api/v1/auth/forgot-password", `{"email":"user@example.com"}`, "", "", 202, false},
		{"/api/v1/auth/reset-password", `{"token":"token","newPassword":"ExamplePass2","confirmPassword":"ExamplePass2"}`, "", "", 200, false},
		{"/api/v1/auth/email/resend", `{"email":"user@example.com"}`, "", "", 202, false},
		{"/api/v1/auth/email/verify", `{"token":"token"}`, "", "", 200, false},
		{"/api/v1/auth/email/resend", `{}`, "", "invalid_email", 400, false},
		{"/api/v1/auth/register/email", `{"email":"user@example.com","password":"ExamplePass1"}`, "", "", 201, true},
		{"/api/v1/auth/login/email", `{"email":"user@example.com","password":"ExamplePass1"}`, "", "", 200, true},
		{"/api/v1/auth/change-password", `{"oldPassword":"ExamplePass1","newPassword":"ExamplePass2","confirmPassword":"ExamplePass2"}`, "valid", "", 200, false},
		{"/api/v1/auth/change-password", `{}`, "", "unauthorized", 401, false},
		{"/api/v1/auth/change-password", `{}`, "rejected", "unauthorized", 401, false},
		{"/api/v1/auth/change-password", `{}`, "valid", "empty_old_password", 400, false},
		{"/api/v1/auth/register/email", `{}`, "", "email_required", 400, false},
		{"/api/v1/auth/login/email", `{}`, "", "email_required", 400, false},
		{"/api/v1/auth/register/email", `{`, "", "invalid_json", 400, false},
		{"/api/v1/dev/send-mail", `{"to":"user@example.com","subject":"test","body":"test"}`, "", "", 200, false},
	} {
		t.Run(tc.path+"/"+tc.token+"/"+tc.code, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: contractCookie(tc.token)})
			}
			w := httptest.NewRecorder()
			handlers := contractHandlers("dev")
			if tc.code == "email_required" {
				handlers.PasswordHandler = passwordhttp.New(passwordFault{accountdomain.ErrEmailRequired}, zap.NewNop())
			}
			New(handlers).ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected status/content type: %d %s", w.Code, w.Body.String())
			}
			response, ok := doc.Paths[tc.path]["post"].Responses[strconv.Itoa(w.Code)]
			if !ok {
				t.Fatal("response status absent from Swagger")
			}
			schema := doc.Definitions[strings.TrimPrefix(response.Schema.Ref, "#/definitions/")]
			var fields map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != len(schema.Properties) {
				t.Fatal("response differs from schema")
			}
			for name := range fields {
				if _, ok := schema.Properties[name]; !ok {
					t.Fatalf("undocumented JSON field %s", name)
				}
			}
			if fields["code"] != tc.code {
				t.Fatalf("unexpected error code: %v", fields)
			}
			cookies := w.Result().Cookies()
			switch {
			case tc.cookie:
				if len(cookies) != 1 || cookies[0].Name != sessionhttp.SessionCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteLaxMode {
					t.Fatal("session cookie contract changed")
				}
			case tc.status == 200 && (tc.path == "/api/v1/auth/change-password" || tc.path == "/api/v1/auth/reset-password"):
				if len(cookies) != 1 || cookies[0].MaxAge != -1 {
					t.Fatal("session cookie not cleared")
				}
			case len(cookies) != 0:
				t.Fatal("unexpected Set-Cookie")
			}
		})
	}
	operation := doc.Paths["/api/v1/auth/change-password"]["post"]
	if !strings.Contains(operation.Description, sessionhttp.SessionCookieName) || !strings.Contains(operation.Description, "not implemented") {
		t.Fatal("missing cookie/security limitations")
	}
}
