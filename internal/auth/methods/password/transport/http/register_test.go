package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func TestRegister_EmailRequired(t *testing.T) {
	service := &mockPasswordService{}
	service.On("Register", mock.Anything, "", "Password123", mock.Anything, mock.Anything).Return(nil, accountdomain.ErrEmailRequired)
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"password":"Password123"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertExpectations(t)
}

func TestRegister_InvalidJSON(t *testing.T) {
	service := &mockPasswordService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{invalid-json`),
	)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertNotCalled(
		t,
		"Register",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestRegister_PasswordRequired(t *testing.T) {
	service := &mockPasswordService{}
	service.On("Register", mock.Anything, "test@mail.ru", "", mock.Anything, mock.Anything).Return(nil, passworddomain.ErrPasswordRequired)
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"email":"test@mail.ru"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertExpectations(t)
}

func TestRegister_ServiceError(t *testing.T) {
	service := &mockPasswordService{}

	service.
		On(
			"Register",
			mock.Anything,
			"test@mail.ru",
			"Password123",
			mock.Anything,
			mock.Anything,
		).
		Return(
			nil,
			passworddomain.ErrEmailAlreadyExists,
		)

	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`
			{
			"email":"test@mail.ru",
			"password":"Password123"
			}
	`,
		),
	)

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	service.AssertExpectations(t)
}

func TestRegister_Success(t *testing.T) {
	service := &mockPasswordService{}

	expiresAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	userID := accountdomain.UserID("user-1")

	service.
		On(
			"Register",
			mock.Anything,
			"test@mail.ru",
			"Password123",
			mock.Anything,
			mock.Anything,
		).
		Return(
			&passwordservice.RegisterResult{
				UserID:    userID,
				Token:     "RawToken",
				ExpiresAt: expiresAt,
			},
			nil,
		)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"email":"test@mail.ru","password":"Password123"}`),
	)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := New(service, zap.NewNop())

	handler.Register(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response RegisterResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, userID, response.UserID)
	assert.NotEmpty(t, rr.Result().Cookies())

	service.AssertExpectations(t)
}

func TestCredentialValidationHTTP(t *testing.T) {
	h := New(passwordservice.New(nil, nil, nil, nil), zap.NewNop())
	for _, tc := range []struct {
		email, password, code string
	}{
		{"", "", "email_required"},
		{"", "Password123", "email_required"},
		{"user@example.com", "", "password_required"},
		{"bad", "", "password_required"},
		{"   ", "", "password_required"},
		{"bad", "Password123", "invalid_email"},
		{"   ", "Password123", "email_required"},
	} {
		for _, endpoint := range []struct {
			name   string
			handle http.HandlerFunc
		}{{"register", h.Register}, {"login", h.LoginByEmail}} {
			t.Run(endpoint.name+"/"+tc.email+"/"+tc.code, func(t *testing.T) {
				body, err := json.Marshal(RegisterRequest{Email: tc.email, Password: tc.password})
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				endpoint.handle(w, r)
				var response struct{ Code string }
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if w.Code != 400 || response.Code != tc.code || len(w.Result().Cookies()) != 0 {
					t.Fatal(w.Code, response.Code)
				}
			})
		}
	}
}
