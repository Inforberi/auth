package register_http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	register_domain "github.com/Inforberi/financial-intelligence/internal/featers/register/domain"
	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestRegisterByEmail_Success(t *testing.T) {
	service := &mockRegisterService{}
	handler := New(service, zap.NewNop())

	expiresAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	userID := domain.UserID("user-1")

	service.
		On(
			"RegisterByEmail",
			mock.Anything,
			"test@mail.ru",
			"Password123",
			mock.Anything,
			mock.Anything,
		).
		Return(
			&register_domain.RegisterResult{
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

	handler.RegisterByEmail(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var response RegisterByEmailResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, userID, response.UserID)
	assert.NotEmpty(t, rr.Result().Cookies())

	service.AssertExpectations(t)
}

func TestRegisterByEmail_InvalidJSON(t *testing.T) {
	service := &mockRegisterService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{invalid-json`),
	)
	rr := httptest.NewRecorder()

	handler.RegisterByEmail(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertNotCalled(
		t,
		"RegisterByEmail",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestRegisterByEmail_EmailRequired(t *testing.T) {
	service := &mockRegisterService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"password":"Password123"}`),
	)
	rr := httptest.NewRecorder()

	handler.RegisterByEmail(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertNotCalled(
		t,
		"RegisterByEmail",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestRegisterByEmail_PasswordRequired(t *testing.T) {
	service := &mockRegisterService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"email":"test@mail.ru"}`),
	)
	rr := httptest.NewRecorder()

	handler.RegisterByEmail(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertNotCalled(
		t,
		"RegisterByEmail",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestRegisterByEmail_ServiceError(t *testing.T) {
	service := &mockRegisterService{}

	service.
		On(
			"RegisterByEmail",
			mock.Anything,
			"test@mail.ru",
			"Password123",
			mock.Anything,
			mock.Anything,
		).
		Return(
			nil,
			register_service.ErrEmailAlreadyExists,
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

	handler.RegisterByEmail(rr, req)

	assert.Equal(
		t,
		http.StatusConflict,
		rr.Code,
	)
	service.AssertExpectations(t)
}
