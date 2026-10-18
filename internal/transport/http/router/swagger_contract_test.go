package router

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func TestSwaggerMatchesRoutes(t *testing.T) {
	doc := readAPI(t)
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			routes := map[string]bool{}
			h := contractHandlers(env)
			h.Config.JWT.NativeEnabled = true
			h.NativeTokens = nativeContractHandlers(&nativeContract{}).NativeTokens
			h.Config.JWT.Enabled = true
			h.Introspection = tokenhttp.NewIntrospection(&introspectionContract{})
			h.Tokens = tokenhttp.New(&contractExchange{}, []byte(`{"keys":[]}`), zap.NewNop())
			err := chi.Walk(New(h), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
				if method == http.MethodOptions {
					return nil
				} // Transport preflight is rejected, not an application operation.
				routes[strings.ToLower(method)+" "+path] = true
				if _, ok := doc.Paths[path][strings.ToLower(method)]; !ok {
					t.Errorf("undocumented route: %s %s", method, path)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for path, methods := range doc.Paths {
				for method := range methods {
					present := routes[method+" "+path]
					if strings.HasPrefix(path, "/api/v1/platform/") {
						if present {
							t.Fatal("standalone exposes a platform route")
						}
						continue // Covered against the distinct operator profile below.
					}
					if env == "prod" && path == "/api/v1/dev/send-mail" {
						if present {
							t.Fatal("dev route exposed in production")
						}
						continue
					}
					if !present {
						t.Errorf("documented route missing: %s %s", method, path)
					}
				}
			}
		})
	}
}

func TestSwaggerMatchesPlatformRoutes(t *testing.T) {
	doc := readAPI(t)
	h := contractHandlers("prod")
	h.Config = &config.Config{Platform: config.PlatformConfig{Enabled: true, RealmID: "1c82c477-3a57-4823-8c49-a476550d8a21", Origin: "https://console.auth.example"}}
	h.Config.MFA.Enabled, h.Config.MFA.RecoveryEnabled, h.Config.InitialSetup.Enabled = true, true, true
	h.Config.Browser.AllowedOrigins = []string{h.Config.Platform.Origin}
	h.Config.Server.TLSCertFile, h.Config.Server.TLSKeyFile = "tls.crt", "tls.key"
	h.Config.Password.ResetURL = h.Config.Platform.Origin + "/reset"
	h.Projects = projecthttp.New(&operatorReadCatalog{}, zap.NewNop())
	handler, err := NewOperator(h)
	if err != nil {
		t.Fatal(err)
	}
	router, ok := handler.(chi.Routes)
	if !ok {
		t.Fatal("operator is not a chi router")
	}
	routes := make(map[string]bool)
	if err := chi.Walk(router, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodOptions {
			return nil
		}
		routes[strings.ToLower(method)+" "+path] = true
		if _, ok := doc.Paths[path][strings.ToLower(method)]; !ok {
			t.Errorf("undocumented operator route: %s %s", method, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for path, methods := range doc.Paths {
		if strings.HasPrefix(path, "/api/v1/platform/") {
			for method := range methods {
				if !routes[method+" "+path] {
					t.Errorf("documented platform route missing: %s %s", method, path)
				}
			}
		}
	}
}

func TestSwaggerMatchesDTOs(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		name string
		dto  any
	}{
		{"project_http.ProjectResponse", projecthttp.ProjectResponse{}},
		{"project_http.ProjectPageResponse", projecthttp.ProjectPageResponse{Projects: []projecthttp.ProjectResponse{}}},
		{"token_http.IntrospectionRequest", tokenhttp.IntrospectionRequest{}},
		{"token_http.IntrospectionResponse", tokenhttp.IntrospectionResponse{Active: true, Issuer: "issuer", Subject: "user", SessionID: "session", ID: "token", Audience: "orders", ExpiresAt: 1, Scope: "orders.read"}},
		{"token_http.ExchangeRequest", tokenhttp.ExchangeRequest{Scope: []accessdomain.PermissionKey{}}},
		{"token_http.ExchangeResponse", tokenhttp.ExchangeResponse{}},
		{"token_http.NativePasswordRequest", tokenhttp.NativePasswordRequest{Scope: []accessdomain.PermissionKey{}}},
		{"token_http.NativeEmailRequest", tokenhttp.NativeEmailRequest{Scope: []accessdomain.PermissionKey{}}},
		{"token_http.NativeEmailConfirmRequest", tokenhttp.NativeEmailConfirmRequest{}},
		{"token_http.NativeEmailResponse", tokenhttp.NativeEmailResponse{}},
		{"token_http.NativeMFARequest", tokenhttp.NativeMFARequest{}},
		{"token_http.NativeEnrollmentRequest", tokenhttp.NativeEnrollmentRequest{}},
		{"token_http.NativeEnrollmentConfirmRequest", tokenhttp.NativeEnrollmentConfirmRequest{}},
		{"token_http.NativeEnrollmentResponse", tokenhttp.NativeEnrollmentResponse{}},
		{"token_http.NativeRecoveryCodesResponse", tokenhttp.NativeRecoveryCodesResponse{Codes: []string{}}},
		{"token_http.NativeChallengeResponse", tokenhttp.NativeChallengeResponse{}},
		{"token_http.RefreshRequest", tokenhttp.RefreshRequest{}},
		{"token_http.JWKSResponse", tokenhttp.JWKSResponse{Keys: []tokenhttp.PublicKey{}}},
		{"token_http.PublicKey", tokenhttp.PublicKey{Operations: []string{"verify"}}},
		{"password_http.ForgotRequest", passwordhttp.ForgotRequest{}},
		{"password_http.ResetRequest", passwordhttp.ResetRequest{}},
		{"password_http.ProtectedRecoveryRequest", passwordhttp.ProtectedRecoveryRequest{}},
		{"password_http.ActivationRequest", passwordhttp.ActivationRequest{}},
		{"password_http.TemporaryLoginRequest", passwordhttp.TemporaryLoginRequest{}},
		{"password_http.TemporaryLoginResponse", passwordhttp.TemporaryLoginResponse{}},
		{"password_http.TemporaryCompleteRequest", passwordhttp.TemporaryCompleteRequest{}},
		{"password_http.ReauthenticationRequest", passwordhttp.ReauthenticationRequest{}},
		{"password_http.ReauthenticationResponse", passwordhttp.ReauthenticationResponse{}},
		{"password_http.RecoveryResponse", passwordhttp.RecoveryResponse{}},
		{"account_http.ResendRequest", accounthttp.ResendRequest{}},
		{"account_http.ConfirmRequest", accounthttp.ConfirmRequest{}},
		{"account_http.VerificationResponse", accounthttp.VerificationResponse{}},
		{"account_http.EmailChangeRequest", accounthttp.EmailChangeRequest{}},
		{"account_http.EmailChangeConfirmRequest", accounthttp.EmailChangeConfirmRequest{}},
		{"account_http.EmailChangeReportRequest", accounthttp.EmailChangeReportRequest{}},
		{"password_http.RegisterRequest", passwordhttp.RegisterRequest{}},
		{"password_http.RegisterResponse", passwordhttp.RegisterResponse{VerificationRequired: true}},
		{"password_http.LoginByEmailRequest", passwordhttp.LoginByEmailRequest{}},
		{"password_http.LoginByEmailResponse", passwordhttp.LoginByEmailResponse{}},
		{"password_http.ChangePasswordRequest", passwordhttp.ChangePasswordRequest{}},
		{"password_http.ChangePasswordResponse", passwordhttp.ChangePasswordResponse{}},
		{"dev.SendMailRequest", dev.SendMailRequest{}},
		{"dev.SendMailResponse", dev.SendMailResponse{}},
		{"httpx.ErrorResponse", httpx.ErrorResponse{}},
		{"router.HealthResponse", HealthResponse{}},
		{"http.MeResponse", sessionhttp.MeResponse{}},
		{"emailotp_http.RequestCodeRequest", otphttp.RequestCodeRequest{}},
		{"emailotp_http.ConfirmCodeRequest", otphttp.ConfirmCodeRequest{}},
		{"emailotp_http.StatusResponse", otphttp.StatusResponse{}},
		{"oidchttp.StartResponse", oidchttp.StartResponse{}},
		{"oidchttp.CallbackResponse", oidchttp.CallbackResponse{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, ok := doc.Definitions[tc.name]
			if !ok || schema.Type != "object" {
				t.Fatal("missing object schema")
			}
			encoded, err := json.Marshal(tc.dto)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != len(schema.Properties) {
				t.Fatal("JSON field count differs from schema")
			}
			for name, value := range fields {
				expectedType := "string"
				switch value.(type) {
				case bool:
					expectedType = "boolean"
				case float64:
					expectedType = "integer"
				case []any:
					expectedType = "array"
				}
				if schema.Properties[name].Type != expectedType {
					t.Errorf("missing/wrong JSON property %s", name)
				}
			}
			typ := reflect.TypeOf(tc.dto)
			var required []string
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.Tag.Get("binding") == "required" {
					required = append(required, strings.Split(field.Tag.Get("json"), ",")[0])
				}
			}
			slices.Sort(required)
			actual := slices.Clone(schema.Required)
			slices.Sort(actual)
			if !slices.Equal(actual, required) {
				t.Fatalf("required fields mismatch: %v != %v", actual, required)
			}
		})
	}
}

func TestSwaggerRequestAndResponseReferences(t *testing.T) {
	doc := readAPI(t)
	requests := map[string]string{
		"/api/v1/auth/token/exchange":              "token_http.ExchangeRequest",
		"/api/v1/auth/email-otp/request":           "emailotp_http.RequestCodeRequest",
		"/api/v1/auth/email-otp/confirm":           "emailotp_http.ConfirmCodeRequest",
		"/api/v1/auth/temporary-password/login":    "password_http.TemporaryLoginRequest",
		"/api/v1/auth/temporary-password/complete": "password_http.TemporaryCompleteRequest",
		"/api/v1/auth/invitations/activate":        "password_http.ActivationRequest",
		"/api/v1/auth/forgot-password":             "password_http.ForgotRequest",
		"/api/v1/auth/reset-password":              "password_http.ResetRequest",
		"/api/v1/auth/email/resend":                "account_http.ResendRequest",
		"/api/v1/auth/email/verify":                "account_http.ConfirmRequest",
		"/api/v1/auth/email/change":                "account_http.EmailChangeRequest",
		"/api/v1/auth/email/change/confirm":        "account_http.EmailChangeConfirmRequest",
		"/api/v1/auth/email/change/report":         "account_http.EmailChangeReportRequest",
		"/api/v1/auth/email/change/recover":        "password_http.ProtectedRecoveryRequest",
		"/api/v1/auth/register/email":              "password_http.RegisterRequest",
		"/api/v1/auth/login/email":                 "password_http.LoginByEmailRequest",
		"/api/v1/auth/change-password":             "password_http.ChangePasswordRequest",
		"/api/v1/dev/send-mail":                    "dev.SendMailRequest",
	}
	for path, methods := range doc.Paths {
		for method, operation := range methods {
			if name, ok := requests[path]; ok {
				if method != "post" || len(operation.Parameters) != 2 {
					t.Fatalf("%s: unexpected request parameters", path)
				}
				body := operation.Parameters[1]
				origin := operation.Parameters[0]
				if origin.In != "header" || origin.Name != "Origin" || !origin.Required {
					t.Fatalf("%s: missing Origin contract", path)
				}
				if body.In != "body" || !body.Required || body.Schema.Ref != "#/definitions/"+name {
					t.Fatalf("%s: incorrect body contract", path)
				}
				if !slices.Equal(operation.Consumes, []string{"application/json"}) || !slices.Equal(operation.Produces, []string{"application/json"}) {
					t.Fatalf("%s: incorrect media types", path)
				}
			}
			if len(operation.Responses) == 0 {
				t.Fatalf("%s: no responses", path)
			}
			for status, response := range operation.Responses {
				if response.Schema.Ref != "" {
					name := strings.TrimPrefix(response.Schema.Ref, "#/definitions/")
					if _, ok := doc.Definitions[name]; !ok {
						t.Errorf("%s %s: broken schema reference %s", path, status, name)
					}
				} else if response.Schema.Type != "string" && status != "204" && status != "304" {
					t.Errorf("%s %s: unknown inline response schema", path, status)
				}
			}
		}
	}
}
