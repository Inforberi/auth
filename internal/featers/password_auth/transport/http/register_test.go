package password_http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	password_service "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestRegister_Success(t *testing.T) {
	service := &mockPasswordService{}

	expiresAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	userID := domain.UserID("user-1")

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
			&password_domain.RegisterResult{
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

func TestRegister_InvalidJSON(t *testing.T) {
	service := &mockPasswordService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{invalid-json`),
	)
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

func TestRegister_EmailRequired(t *testing.T) {
	service := &mockPasswordService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"password":"Password123"}`),
	)
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
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"email":"test@mail.ru"}`),
	)
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
			password_service.ErrEmailAlreadyExists,
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

	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	service.AssertExpectations(t)
}
