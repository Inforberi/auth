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

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestRegister_Success(t *testing.T) {
	service := &mockPasswordService{}

	expiresAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	userID := accountmodel.UserID("user-1")

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
			&passwordmodel.RegisterResult{
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
