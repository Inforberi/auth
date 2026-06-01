package login_http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestLoginByEmail_Success(t *testing.T) {
	user := domain.UserID("user-1")
	token := "RawToken"
	expiresAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	service := &mockLoginService{}

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login/email",
		strings.NewReader(`{
					"email":"test@mail.ru",
					"password":"Password12345"
			}`),
	)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()

	service.On(
		"Login",
		req.Context(),
		login_domain.LoginInput{
			Email:     "test@mail.ru",
			Password:  "Password12345",
			UserAgent: "test-agent",
			IP:        "127.0.0.1",
		},
	).Return(
		&login_domain.LoginResult{
			UserID:    user,
			Token:     token,
			ExpiresAt: expiresAt,
		},
		nil,
	)

	handler := New(service, zap.NewNop())

	handler.LoginByEmail(rr, req)

	var response LoginByEmailResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", response.Status)

	service.AssertExpectations(t)
}
